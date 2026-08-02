/**
 * TLS 1.3 key schedule (RFC 8446 §7.1).
 *
 * Derives all handshake and application traffic secrets from the (EC)DHE shared
 * secret and the running handshake transcript. Every HMAC/HKDF/hash operation is
 * delegated to @network/crypto — this module owns the schedule structure only.
 *
 * HKDF-Extract and HKDF-Expand are implemented locally on top of the HMAC
 * primitive exposed by @network/crypto: the provider's combined `hkdf` helper
 * always performs extract+expand in one call, but the TLS 1.3 schedule needs
 * the two steps independently (the extract output feeds the next stage's salt).
 */

import { crypto, SHA_256, SHA_384 } from "@network/crypto";
import type { HashId } from "@network/crypto";
import type {
    ApplicationTrafficSecrets,
    CipherSuite,
    ProtocolVersion,
    TrafficSecrets,
} from "../types.js";
import { TlsHandshakeError } from "../errors.js";
import { assertNever } from "../utils.js";

/** Map a cipher suite to its HKDF hash function (all TLS 1.3 suites use SHA-256/384). */
export function cipherSuiteToHash(cipherSuite: CipherSuite): HashId {
    switch (cipherSuite) {
        case "TLS_AES_256_GCM_SHA384":
            return SHA_384;
        case "TLS_AES_128_GCM_SHA256":
        case "TLS_CHACHA20_POLY1305_SHA256":
        case "TLS_AES_128_CCM_SHA256":
            return SHA_256;
    }
}

/** Map a cipher suite to its AEAD key length in bytes. */
export function cipherSuiteKeyLength(cipherSuite: CipherSuite): number {
    switch (cipherSuite) {
        case "TLS_AES_128_GCM_SHA256":
        case "TLS_AES_128_CCM_SHA256":
            return 16;
        case "TLS_AES_256_GCM_SHA384":
        case "TLS_CHACHA20_POLY1305_SHA256":
            return 32;
    }
}

/** Map a cipher suite to its AEAD IV length in bytes (all TLS 1.3 AEADs use 12). */
export function cipherSuiteIvLength(_cipherSuite: CipherSuite): number {
    return 12;
}

/** Hash output length for a given HKDF hash (bytes). */
function hashLength(hash: HashId): number {
    switch (hash) {
        case "SHA-256":
            return 32;
        case "SHA-384":
            return 48;
        default:
            return assertNever(hash);
    }
}

/**
 * HKDF-Extract(salt, Ikm) = HMAC-Hash(salt, Ikm), per RFC 5869 §2.3.
 * The output is exactly {@link hashLength}(hash) bytes.
 */
function hkdfExtract(hash: HashId, salt: Uint8Array, ikm: Uint8Array): Uint8Array {
    return crypto.hmac(hash, salt, ikm) as Uint8Array;
}

/**
 * HKDF-Expand(PRK, info, length) per RFC 5869 §2.3, implemented on top of HMAC
 * because @network/crypto exposes only the combined extract+expand helper.
 */
function hkdfExpand(hash: HashId, prk: Uint8Array, info: Uint8Array, length: number): Uint8Array {
    const hashLen = hashLength(hash);
    const n = Math.ceil(length / hashLen);
    if (n > 255) {
        throw new Error(`HKDF-Expand length ${length} exceeds maximum for hash (255 * ${hashLen})`);
    }
    const okm = new Uint8Array(n * hashLen);
    let t: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
    for (let i = 1; i <= n; i++) {
        const block = new Uint8Array(t.length + info.length + 1);
        block.set(t, 0);
        block.set(info, t.length);
        block[block.length - 1] = i;
        t = crypto.hmac(hash, prk, block);
        okm.set(t, (i - 1) * hashLen);
    }
    return okm.subarray(0, length);
}

/**
 * HKDF-Expand-Label per RFC 8446 §7.1.
 *
 *   HKDF-Expand-Label(Secret, Label, Context, Length) =
 *       HKDF-Expand(Secret, HkdfLabel, Length)
 *
 * where HkdfLabel is the TLS-encoded struct { length, label, context }.
 */
export function hkdfExpandLabel(
    secret: Uint8Array,
    label: string,
    context: Uint8Array,
    length: number,
    hash: HashId,
): Uint8Array {
    const prefix = "tls13 ";
    const labelBytes = new TextEncoder().encode(prefix + label);
    // HkdfLabel: uint16 length || uint8 label_len || label || uint8 ctx_len || context.
    const hkdfLabel = new Uint8Array(2 + 1 + labelBytes.length + 1 + context.length);
    let o = 0;
    hkdfLabel[o++] = (length >> 8) & 0xff;
    hkdfLabel[o++] = length & 0xff;
    hkdfLabel[o++] = labelBytes.length & 0xff;
    hkdfLabel.set(labelBytes, o);
    o += labelBytes.length;
    hkdfLabel[o++] = context.length & 0xff;
    hkdfLabel.set(context, o);
    return hkdfExpand(hash, secret, hkdfLabel, length);
}

/**
 * Derive a single direction's traffic secrets (key + iv) from a traffic secret.
 */
function deriveTrafficSecrets(
    trafficSecret: Uint8Array,
    cipherSuite: CipherSuite,
    hash: HashId,
): TrafficSecrets {
    const key = hkdfExpandLabel(trafficSecret, "key", new Uint8Array(0), cipherSuiteKeyLength(cipherSuite), hash);
    const iv = hkdfExpandLabel(trafficSecret, "iv", new Uint8Array(0), cipherSuiteIvLength(cipherSuite), hash);
    return { key, iv };
}

/**
 * Derive the handshake traffic secrets from the (EC)DHE shared secret and the
 * ClientHello..ServerHello transcript. Returns secrets for both directions.
 *
 * @param sharedSecret    (EC)DHE shared secret from @network/crypto.
 * @param helloTranscript Transcript hash of ClientHello..ServerHello.
 * @param cipherSuite     Negotiated cipher suite (selects hash + AEAD sizes).
 */
export function deriveHandshakeSecrets(
    sharedSecret: Uint8Array,
    helloTranscript: Uint8Array,
    cipherSuite: CipherSuite,
): {
    masterSecret: Uint8Array;
    traffic: ApplicationTrafficSecrets;
} {
    const hash = cipherSuiteToHash(cipherSuite);
    const hashLen = hashLength(hash);
    const zeros = new Uint8Array(hashLen);

    // early_secret = HKDF-Extract(0, 0)
    const earlySecret = hkdfExtract(hash, zeros, zeros);

    // derived = HKDF-Expand-Label(early_secret, "derived", "", Hash.length)
    const derived = hkdfExpandLabel(earlySecret, "derived", new Uint8Array(0), hashLen, hash);

    // handshake_secret = HKDF-Extract(derived, sharedSecret)
    const handshakeSecret = hkdfExtract(hash, derived, sharedSecret);

    // client/server handshake traffic secrets.
    const clientHsTraffic = hkdfExpandLabel(handshakeSecret, "c hs traffic", helloTranscript, hashLen, hash);
    const serverHsTraffic = hkdfExpandLabel(handshakeSecret, "s hs traffic", helloTranscript, hashLen, hash);

    // master_secret = HKDF-Extract(Derive-Secret(handshake_secret, "derived", ""), 0)
    const masterDerived = hkdfExpandLabel(handshakeSecret, "derived", new Uint8Array(0), hashLen, hash);
    const masterSecret = hkdfExtract(hash, masterDerived, zeros);

    return {
        masterSecret,
        traffic: {
            client: deriveTrafficSecrets(clientHsTraffic, cipherSuite, hash),
            server: deriveTrafficSecrets(serverHsTraffic, cipherSuite, hash),
        },
    };
}

/**
 * Derive the application traffic secrets from the master secret and the
 * ClientHello..server Finished transcript.
 *
 * @param masterSecret        Master secret returned by {@link deriveHandshakeSecrets}.
 * @param handshakeTranscript Transcript hash of ClientHello..server Finished.
 * @param cipherSuite         Negotiated cipher suite (selects hash + AEAD sizes).
 */
export function deriveApplicationSecrets(
    masterSecret: Uint8Array,
    handshakeTranscript: Uint8Array,
    cipherSuite: CipherSuite,
): ApplicationTrafficSecrets {
    const hash = cipherSuiteToHash(cipherSuite);
    const hashLen = hashLength(hash);

    const clientApTraffic = hkdfExpandLabel(masterSecret, "c ap traffic", handshakeTranscript, hashLen, hash);
    const serverApTraffic = hkdfExpandLabel(masterSecret, "s ap traffic", handshakeTranscript, hashLen, hash);

    return {
        client: deriveTrafficSecrets(clientApTraffic, cipherSuite, hash),
        server: deriveTrafficSecrets(serverApTraffic, cipherSuite, hash),
    };
}

/**
 * Re-derive traffic secrets for a KeyUpdate (post-handshake). TLS 1.3 only.
 *
 *   application_traffic_secret_N+1 =
 *       HKDF-Expand-Label(application_traffic_secret_N, "traffic upd", "", Hash.length)
 *
 * @param currentSecret The current application traffic secret (Hash.length bytes).
 * @param cipherSuite   Negotiated cipher suite (selects hash + AEAD sizes).
 */
export function updateTrafficSecrets(currentSecret: Uint8Array, cipherSuite: CipherSuite): TrafficSecrets {
    const hash = cipherSuiteToHash(cipherSuite);
    const hashLen = hashLength(hash);
    const nextSecret = hkdfExpandLabel(currentSecret, "traffic upd", new Uint8Array(0), hashLen, hash);
    return deriveTrafficSecrets(nextSecret, cipherSuite, hash);
}

/** Validate that the server selected a cipher suite we actually offered. */
export function assertCipherSuiteOffered(selected: CipherSuite, offered: readonly CipherSuite[]): void {
    if (!offered.includes(selected)) {
        throw new TlsHandshakeError("server_hello", {
            cause: new Error(`server selected unoffered cipher suite: ${selected}`),
        });
    }
}

/** Protocol versions we are willing to negotiate. */
const SUPPORTED_VERSIONS = new Set<ProtocolVersion["name"]>(["TLS 1.2", "TLS 1.3"]);

/** Validate that the server negotiated a version we support. */
export function assertVersionSupported(selected: ProtocolVersion): void {
    if (!SUPPORTED_VERSIONS.has(selected.name)) {
        throw new TlsHandshakeError("server_hello", {
            cause: new Error(`unsupported protocol version: ${selected.name}`),
        });
    }
}

void assertNever;
