/**
 * (EC)DHE key exchange and transcript verification for the TLS 1.3 handshake.
 *
 * These are the cryptographic heart of the handshake — recovering the server's
 * key share to derive the shared secret, hashing the transcript, and verifying
 * (and producing) the Finished HMAC. They are pure computations over their
 * inputs and the @browsercore/crypto backend; they deliberately hold no
 * connection state, so the connection class can stay an orchestrator that wires
 * them together.
 */

import type { CryptoProvider, HashId } from "@browsercore/crypto";
import type { KeyPair } from "../types.js";
import type { ServerHello } from "../handshake/handshake.js";
import { TlsHandshakeError } from "../errors.js";
import { ExtensionType, findExtension, parseExtensions, wireToNamedGroup } from "../extensions/extensions.js";
import { hkdfExpandLabel, hashLengthFor } from "../crypto/keySchedule.js";
import { assertNever, constantTimeEqual } from "../utils.js";

/** Compute the (EC)DHE shared secret from the server's selected key share. */
export function computeSharedSecret(serverHello: ServerHello, keyPairs: readonly KeyPair[], provider: CryptoProvider): Uint8Array {
    const extensions = parseExtensions(serverHello.extensions);
    const keyShare = findExtension(extensions, ExtensionType.KEY_SHARE);
    if (keyShare === undefined) {
        throw new TlsHandshakeError("server_hello", {
            cause: new Error("ServerHello missing required key_share extension"),
        });
    }
    // Server KeyShareEntry: group(2) || len(2) || key_exchange.
    if (keyShare.data.length < 4) {
        throw new TlsHandshakeError("server_hello", {
            cause: new Error("key_share entry truncated"),
        });
    }
    // The length check above guarantees indices 0..3 are in bounds, but
    // noUncheckedIndexedAccess cannot prove it — read through locals.
    const d0 = keyShare.data[0];
    const d1 = keyShare.data[1];
    const d2 = keyShare.data[2];
    const d3 = keyShare.data[3];
    if (d0 === undefined || d1 === undefined || d2 === undefined || d3 === undefined) {
        throw new TlsHandshakeError("server_hello", {
            cause: new Error("key_share entry data truncated"),
        });
    }
    const group = wireToNamedGroup((d0 << 8) | d1);
    const keyLen = (d2 << 8) | d3;
    if (keyLen + 4 !== keyShare.data.length) {
        throw new TlsHandshakeError("server_hello", {
            cause: new Error("key_share key_exchange length mismatch"),
        });
    }
    const serverPublicKey = keyShare.data.subarray(4, 4 + keyLen);
    // Post-quantum hybrid groups (X25519MLKEM768, X25519Kyber768) are advertised
    // in supported_groups and key_share for fingerprint compatibility, but the
    // crypto backend has no post-quantum support. When a server selects one, we
    // look up the hybrid-tagged key pair (which holds an X25519 key) and perform
    // the classical X25519 exchange against the server's classical key share.
    const isHybrid = group === "X25519MLKEM768" || group === "X25519Kyber768";
    const exchangeGroup = isHybrid ? "x25519" : group;
    // Prefer a key pair tagged with the actual negotiated group (handles both
    // the hybrid case, where we tag as the hybrid name, and the direct case).
    // Fall back to x25519 for hybrid groups if no hybrid-tagged pair exists
    // (backward compat with profiles that only offer x25519).
    const myPair = keyPairs.find((kp) => kp.algorithm === group)
        ?? (isHybrid ? keyPairs.find((kp) => kp.algorithm === "x25519") : undefined);
    if (myPair === undefined) {
        throw new TlsHandshakeError("server_hello", {
            cause: new Error(`server selected key share group ${group} we did not offer`),
        });
    }
    switch (exchangeGroup) {
        case "x25519":
            return provider.x25519SharedSecret(myPair.privateKey, serverPublicKey);
        case "secp256r1":
        case "secp384r1":
            return provider.ecdhSharedSecret(exchangeGroup, myPair.privateKey, serverPublicKey);
        case "secp521r1":
        case "x448":
        case "ffdhe2048":
        case "ffdhe3072":
            // @browsercore/crypto only exposes X25519 and the two NIST ECDH
            // curves (secp256r1, secp384r1) today. Other (EC)DHE groups
            // (secp521r1, x448, FFDHE) would need a backend we do not have —
            // fail fast and typed rather than producing a bogus secret.
            throw new TlsHandshakeError("server_hello", {
                cause: new Error(`key exchange for group ${exchangeGroup} is not supported by the crypto backend`),
            });
        default:
            // All NamedGroup members are handled above — this is unrepresentable.
            return assertNever(exchangeGroup);
    }
}

/** Hash the current handshake transcript with the negotiated cipher's hash. */
export function transcriptHash(transcript: readonly Uint8Array[], hash: HashId, provider: CryptoProvider): Uint8Array {
    const blob = transcript.reduce((acc, msg) => {
        const next = new Uint8Array(acc.length + msg.length);
        next.set(acc, 0);
        next.set(msg, acc.length);
        return next;
    }, new Uint8Array(0));
    return hash === "SHA-384" ? provider.sha384(blob) : provider.sha256(blob);
}

/**
 * Verify the server's Finished message: HMAC(finished_key, transcript), where
 * finished_key = HKDF-Expand-Label(server_traffic_secret, "finished", "", Hash.length)
 * and the transcript is ClientHello..CertificateVerify (everything before Finished).
 */
export function verifyServerFinished(
    body: Uint8Array,
    transcript: Uint8Array,
    hash: HashId,
    serverHsTrafficSecret: Uint8Array,
    provider: CryptoProvider,
): void {
    const hashLen = hashLengthFor(hash);
    if (body.length !== hashLen) {
        throw new TlsHandshakeError("finished", {
            cause: new Error(`server Finished length ${body.length} != expected ${hashLen}`),
        });
    }
    const finishedKey = hkdfExpandLabel(serverHsTrafficSecret, "finished", new Uint8Array(0), hashLen, hash, provider);
    const expected = provider.hmac(hash, finishedKey, transcript);
    if (!constantTimeEqual(body, expected)) {
        throw new TlsHandshakeError("finished", {
            cause: new Error("server Finished verify_data mismatch"),
        });
    }
}
