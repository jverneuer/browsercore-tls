/**
 * Shared test helpers for TLS tests — an in-memory EventProvider mock and a
 * node:crypto-backed CryptoProvider factory.
 *
 * The TLS connection requires an injected EventProvider (no fallback); every
 * test must inject one. This mock implements the full EventProvider interface
 * so tests can construct connections without pulling in node:events.
 *
 * `createTestCryptoProvider()` returns a COMPLETE `CryptoProvider` backed by
 * `node:crypto` — TLS uses AEAD encryption, HKDF, X25519 key exchange, and
 * hashing, so a throw-on-unimplemented stub (like http2's mock) is not enough.
 * The production Node-backed provider was extracted to browsersmith; this
 * test-local replica mirrors it so protocol packages never import a runtime
 * crypto instance.
 */

import {
    randomBytes as nodeRandomBytes,
    createHash,
    createHmac,
    hkdfSync,
    createCipheriv,
    createDecipheriv,
    createECDH,
    createPublicKey,
    createVerify,
    constants,
} from "node:crypto";

import {
    NobleX25519Backend,
    assertNever,
    DecryptError,
    UnsupportedAlgorithmError,
} from "@browsercore/crypto";
import type { X25519Backend } from "@browsercore/crypto";
import type {
    CryptoProvider,
    EcdhCurve,
    EcdhKeyPair,
    EventProvider,
    HashId,
    X25519KeyPair,
} from "@browsercore/contracts";

/**
 * Create a minimal in-memory EventProvider. Stand-in for the Node
 * EventEmitter-backed provider that browsersmith injects in production.
 *
 * @returns A fresh EventProvider backed by an in-memory listener map.
 */
export function createMockEventProvider(): EventProvider {
    const listeners = new Map<string, Set<(...args: unknown[]) => void>>();
    return {
        on(event, listener) {
            if (!listeners.has(event)) listeners.set(event, new Set());
            listeners.get(event)!.add(listener);
        },
        once(event, listener) {
            const wrapped = (...args: unknown[]) => {
                listeners.get(event)?.delete(wrapped);
                listener(...args);
            };
            this.on(event, wrapped);
        },
        off(event, listener) {
            listeners.get(event)?.delete(listener);
        },
        removeListener(event, listener) {
            listeners.get(event)?.delete(listener);
        },
        emit(event, ...args) {
            const set = listeners.get(event);
            if (!set || set.size === 0) return false;
            for (const l of [...set]) l(...args);
            return true;
        },
        listenerCount(event) {
            return listeners.get(event)?.size ?? 0;
        },
        removeAllListeners(event) {
            if (event) listeners.delete(event);
            else listeners.clear();
        },
    };
}

// ---------------------------------------------------------------------------
// CryptoProvider — node:crypto-backed test implementation
// ---------------------------------------------------------------------------

/** AEAD authentication tag length for every cipher TLS uses (bytes). */
const AEAD_TAG_LENGTH = 16;

/** The four AEAD ciphers this provider supports. */
type TestAeadCipher = "AES-128-GCM" | "AES-256-GCM" | "AES-128-CCM" | "ChaCha20-Poly1305";

/**
 * Map a branded {@link HashId} to the algorithm string `node:crypto` expects.
 */
function hashAlgorithmName(hash: HashId): string {
    switch (hash) {
        case "SHA-256":
            return "sha256";
        case "SHA-384":
            return "sha384";
        default:
            return assertNever(hash);
    }
}

/**
 * Look up the `node:crypto` algorithm string and per-cipher options for a
 * branded AEAD cipher identifier. AES-CCM requires an explicit
 * `authTagLength`; GCM and ChaCha20-Poly1305 use node's default.
 */
function aeadCipherConfig(cipher: TestAeadCipher): {
    algorithm: string;
    authTagLength: number | undefined;
} {
    switch (cipher) {
        case "AES-128-GCM":
            return { algorithm: "aes-128-gcm", authTagLength: undefined };
        case "AES-256-GCM":
            return { algorithm: "aes-256-gcm", authTagLength: undefined };
        case "AES-128-CCM":
            return { algorithm: "aes-128-ccm", authTagLength: AEAD_TAG_LENGTH };
        case "ChaCha20-Poly1305":
            return { algorithm: "chacha20-poly1305", authTagLength: undefined };
        default:
            return assertNever(cipher);
    }
}

/**
 * AEAD-encrypt with a `node:crypto` cipher. Returns ciphertext with the
 * 16-byte authentication tag appended, matching the CryptoProvider contract.
 */
function aeadEncrypt(
    cipher: TestAeadCipher,
    key: Uint8Array,
    nonce: Uint8Array,
    plaintext: Uint8Array,
    aad: Uint8Array,
): Uint8Array {
    const { algorithm, authTagLength } = aeadCipherConfig(cipher);
    const enc =
        authTagLength === undefined
            ? createCipheriv(algorithm, key, nonce)
            : createCipheriv(algorithm, key, nonce, { authTagLength });
    enc.setAAD(aad, { plaintextLength: plaintext.length });
    const out = new Uint8Array(enc.update(plaintext));
    const final = new Uint8Array(enc.final());
    const tag = new Uint8Array(enc.getAuthTag());
    const result = new Uint8Array(out.length + final.length + tag.length);
    result.set(out, 0);
    result.set(final, out.length);
    result.set(tag, out.length + final.length);
    return result;
}

/**
 * AEAD-decrypt with a `node:crypto` cipher. Expects ciphertext with the
 * 16-byte tag appended. Throws {@link DecryptError} on authentication failure.
 */
function aeadDecrypt(
    cipher: TestAeadCipher,
    key: Uint8Array,
    nonce: Uint8Array,
    ciphertextAndTag: Uint8Array,
    aad: Uint8Array,
): Uint8Array {
    if (ciphertextAndTag.length < AEAD_TAG_LENGTH) {
        throw new DecryptError(cipher);
    }
    const { algorithm, authTagLength } = aeadCipherConfig(cipher);
    const tagStart = ciphertextAndTag.length - AEAD_TAG_LENGTH;
    const ciphertext = ciphertextAndTag.subarray(0, tagStart);
    const tag = ciphertextAndTag.subarray(tagStart);
    const dec =
        authTagLength === undefined
            ? createDecipheriv(algorithm, key, nonce)
            : createDecipheriv(algorithm, key, nonce, { authTagLength });
    dec.setAuthTag(tag);
    dec.setAAD(aad, { plaintextLength: ciphertext.length });
    try {
        const plaintext = new Uint8Array(dec.update(ciphertext));
        const final = new Uint8Array(dec.final());
        const out = new Uint8Array(plaintext.length + final.length);
        out.set(plaintext, 0);
        out.set(final, plaintext.length);
        return out;
    } catch (cause) {
        throw new DecryptError(cipher, { cause: cause as Error });
    }
}

/** Map a branded {@link EcdhCurve} to the `node:crypto` curve name. */
function ecdhCurveToNode(curve: EcdhCurve): string {
    switch (curve) {
        case "secp256r1":
            return "prime256v1";
        case "secp384r1":
            return "secp384r1";
        default:
            return assertNever(curve);
    }
}

/**
 * Create a COMPLETE `CryptoProvider` backed by `node:crypto`.
 *
 * TLS uses crypto for AEAD encryption (AES-GCM/CCM, ChaCha20-Poly1305), HKDF
 * key derivation, X25519 key exchange, ECDH, hashing (SHA-256/384), HMAC, and
 * signature verification — so every method is implemented, not stubbed. This
 * mirrors the production `NodeCryptoProvider` that was extracted to browsersmith.
 *
 * @param x25519Backend Optional X25519 backend (defaults to NobleX25519Backend,
 *   the same reference implementation used in production).
 * @returns A fresh CryptoProvider backed by `node:crypto`.
 */
export function createTestCryptoProvider(
    x25519Backend: X25519Backend = new NobleX25519Backend(),
): CryptoProvider {
    return {
        randomBytes(length: number): Uint8Array {
            return nodeRandomBytes(length);
        },
        sha256(data: Uint8Array): Uint8Array {
            return new Uint8Array(createHash("sha256").update(data).digest());
        },
        sha384(data: Uint8Array): Uint8Array {
            return new Uint8Array(createHash("sha384").update(data).digest());
        },
        hkdf(hash: HashId, salt: Uint8Array, ikm: Uint8Array, info: Uint8Array, length: number): Uint8Array {
            // node:crypto.hkdfSync(digest, ikm, salt, info, keylen)
            const digest = hashAlgorithmName(hash);
            const key = hkdfSync(digest, ikm, salt, info, length);
            return new Uint8Array(key.buffer, key.byteOffset, key.byteLength);
        },
        hmac(hash: HashId, key: Uint8Array, data: Uint8Array): Uint8Array {
            const algorithm = hashAlgorithmName(hash);
            return new Uint8Array(createHmac(algorithm, key).update(data).digest());
        },
        aes128GcmEncrypt(key: Uint8Array, nonce: Uint8Array, plaintext: Uint8Array, aad: Uint8Array): Uint8Array {
            return aeadEncrypt("AES-128-GCM", key, nonce, plaintext, aad);
        },
        aes128GcmDecrypt(key: Uint8Array, nonce: Uint8Array, ciphertext: Uint8Array, aad: Uint8Array): Uint8Array {
            return aeadDecrypt("AES-128-GCM", key, nonce, ciphertext, aad);
        },
        aes256GcmEncrypt(key: Uint8Array, nonce: Uint8Array, plaintext: Uint8Array, aad: Uint8Array): Uint8Array {
            return aeadEncrypt("AES-256-GCM", key, nonce, plaintext, aad);
        },
        aes256GcmDecrypt(key: Uint8Array, nonce: Uint8Array, ciphertext: Uint8Array, aad: Uint8Array): Uint8Array {
            return aeadDecrypt("AES-256-GCM", key, nonce, ciphertext, aad);
        },
        aes128CcmEncrypt(key: Uint8Array, nonce: Uint8Array, plaintext: Uint8Array, aad: Uint8Array): Uint8Array {
            return aeadEncrypt("AES-128-CCM", key, nonce, plaintext, aad);
        },
        aes128CcmDecrypt(key: Uint8Array, nonce: Uint8Array, ciphertext: Uint8Array, aad: Uint8Array): Uint8Array {
            return aeadDecrypt("AES-128-CCM", key, nonce, ciphertext, aad);
        },
        chacha20Poly1305Encrypt(key: Uint8Array, nonce: Uint8Array, plaintext: Uint8Array, aad: Uint8Array): Uint8Array {
            return aeadEncrypt("ChaCha20-Poly1305", key, nonce, plaintext, aad);
        },
        chacha20Poly1305Decrypt(key: Uint8Array, nonce: Uint8Array, ciphertext: Uint8Array, aad: Uint8Array): Uint8Array {
            return aeadDecrypt("ChaCha20-Poly1305", key, nonce, ciphertext, aad);
        },
        x25519GenerateKeyPair(): X25519KeyPair {
            const secretKey = nodeRandomBytes(32);
            const publicKey = x25519Backend.publicKey(secretKey);
            return { publicKey, secretKey };
        },
        x25519SharedSecret(secretKey: Uint8Array, peerPublicKey: Uint8Array): Uint8Array {
            return x25519Backend.sharedSecret(secretKey, peerPublicKey);
        },
        ecdhGenerateKeyPair(curve: EcdhCurve): EcdhKeyPair {
            const ecdh = createECDH(ecdhCurveToNode(curve));
            ecdh.generateKeys();
            // getPrivateKey() strips leading zeros — left-pad to fixed width.
            const scalarLength = curve === "secp256r1" ? 32 : 48;
            const rawScalar = ecdh.getPrivateKey();
            const secretKey = new Uint8Array(scalarLength);
            secretKey.set(rawScalar, scalarLength - rawScalar.length);
            return {
                curve,
                publicKey: new Uint8Array(ecdh.getPublicKey()),
                secretKey,
            };
        },
        ecdhSharedSecret(curve: EcdhCurve, secretKey: Uint8Array, peerPublicKey: Uint8Array): Uint8Array {
            const ecdh = createECDH(ecdhCurveToNode(curve));
            ecdh.setPrivateKey(secretKey);
            return new Uint8Array(ecdh.computeSecret(peerPublicKey));
        },
        verifySignature(scheme: string, publicKey: Uint8Array, signature: Uint8Array, data: Uint8Array): boolean {
            const key = createPublicKey({ key: Buffer.from(publicKey), format: "der", type: "spki" });
            switch (scheme) {
                case "ecdsa_secp256r1_sha256":
                    return createVerify("sha256").update(data).verify(key, signature);
                case "ecdsa_secp384r1_sha384":
                    return createVerify("sha384").update(data).verify(key, signature);
                case "rsa_pss_rsae_sha256":
                    return createVerify("sha256").update(data).verify(
                        { key, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 },
                        signature,
                    );
                case "rsa_pss_rsae_sha384":
                    return createVerify("sha384").update(data).verify(
                        { key, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: 48 },
                        signature,
                    );
                case "rsa_pkcs1_sha256":
                    return createVerify("sha256").update(data).verify(
                        { key, padding: constants.RSA_PKCS1_PADDING },
                        signature,
                    );
                default:
                    throw new UnsupportedAlgorithmError(`unsupported signature scheme: ${scheme}`);
            }
        },
        aesEcbEncrypt(key: Uint8Array, block: Uint8Array): Uint8Array {
            const algorithm = key.length === 16 ? "aes-128-ecb" : "aes-256-ecb";
            const cipher = createCipheriv(algorithm, key, new Uint8Array(0));
            cipher.setAutoPadding(false);
            const out = new Uint8Array(cipher.update(block));
            const final = new Uint8Array(cipher.final());
            const result = new Uint8Array(out.length + final.length);
            result.set(out, 0);
            result.set(final, out.length);
            return result;
        },
    };
}
