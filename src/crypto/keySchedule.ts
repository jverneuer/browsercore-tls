/**
 * TLS 1.3 key schedule (RFC 8446 §7.1).
 *
 * Derives all handshake and application traffic secrets from the (EC)DHE shared
 * secret and the running handshake transcript. Every HMAC/HKDF/hash operation is
 * delegated to @browsercore/crypto — this module owns the schedule structure only.
 *
 * HKDF-Extract and HKDF-Expand are implemented locally on top of the HMAC
 * primitive exposed by @browsercore/crypto: the provider's combined `hkdf` helper
 * always performs extract+expand in one call, but the TLS 1.3 schedule needs
 * the two steps independently (the extract output feeds the next stage's salt).
 */

import { crypto, SHA_256, SHA_384, type HashId } from "@browsercore/crypto";
import type {
    ApplicationTrafficSecrets,
    CipherSuite,
    ProtocolVersion,
    TrafficSecrets,
} from "../types.js";
import { TlsHandshakeError, TlsKeyScheduleError } from "../errors.js";
import { assertNever } from "../utils.js";

/**
 * Map a cipher suite to its HKDF hash function.
 *
 * Only the four TLS 1.3 AEAD suites can be negotiated; they all use SHA-256
 * except AES-256-GCM, which uses SHA-384. TLS 1.2 suites can't be negotiated by
 * this client, so the default throws rather than guessing a hash.
 */
export function cipherSuiteToHash(cipherSuite: CipherSuite): HashId {
    switch (cipherSuite) {
        // The four TLS 1.3 AEAD suites — the only ones this client can negotiate.
        case "TLS_AES_256_GCM_SHA384":
            return SHA_384;
        case "TLS_AES_128_GCM_SHA256":
        case "TLS_CHACHA20_POLY1305_SHA256":
        case "TLS_AES_128_CCM_SHA256":
            return SHA_256;
        // TLS 1.2 suites (and the GREASE placeholder) appear only in the offered
        // list and can never be negotiated in TLS 1.3, so they have no HKDF hash.
        case "TLS_GREASE_RESERVED_0":
        case "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256":
        case "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256":
        case "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384":
        case "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384":
        case "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256":
        case "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256":
        case "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA":
        case "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA":
        case "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA":
        case "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA":
        case "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256":
        case "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256":
        case "TLS_RSA_WITH_AES_128_CBC_SHA256":
        case "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384":
        case "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384":
        case "TLS_RSA_WITH_AES_256_CBC_SHA256":
        case "TLS_RSA_WITH_AES_128_GCM_SHA256":
        case "TLS_RSA_WITH_AES_256_GCM_SHA384":
        case "TLS_RSA_WITH_AES_128_CBC_SHA":
        case "TLS_RSA_WITH_AES_256_CBC_SHA":
        case "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA":
        case "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA":
        case "TLS_RSA_WITH_3DES_EDE_CBC_SHA":
            return throwKeyScheduleError(
                `cipher suite ${cipherSuite} has no HKDF hash mapping — not a negotiable TLS 1.3 suite`,
            );
        default:
            // Every CipherSuite member is covered above; this is unreachable but
            // keeps the switch exhaustive if the union is ever extended.
            return assertNever(cipherSuite);
    }
}

/**
 * Map a cipher suite to its AEAD key length in bytes.
 *
 * Only meaningful for the four negotiable TLS 1.3 AEAD suites. TLS 1.2 suites
 * can't be negotiated, so the default throws.
 */
export function cipherSuiteKeyLength(cipherSuite: CipherSuite): number {
    switch (cipherSuite) {
        // The four TLS 1.3 AEAD suites — the only ones this client can negotiate.
        case "TLS_AES_128_GCM_SHA256":
        case "TLS_AES_128_CCM_SHA256":
            return 16;
        case "TLS_AES_256_GCM_SHA384":
        case "TLS_CHACHA20_POLY1305_SHA256":
            return 32;
        // TLS 1.2 suites (and the GREASE placeholder) appear only in the offered
        // list and can never be negotiated in TLS 1.3, so they have no AEAD key length.
        case "TLS_GREASE_RESERVED_0":
        case "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256":
        case "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256":
        case "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384":
        case "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384":
        case "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256":
        case "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256":
        case "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA":
        case "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA":
        case "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA":
        case "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA":
        case "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256":
        case "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256":
        case "TLS_RSA_WITH_AES_128_CBC_SHA256":
        case "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384":
        case "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384":
        case "TLS_RSA_WITH_AES_256_CBC_SHA256":
        case "TLS_RSA_WITH_AES_128_GCM_SHA256":
        case "TLS_RSA_WITH_AES_256_GCM_SHA384":
        case "TLS_RSA_WITH_AES_128_CBC_SHA":
        case "TLS_RSA_WITH_AES_256_CBC_SHA":
        case "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA":
        case "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA":
        case "TLS_RSA_WITH_3DES_EDE_CBC_SHA":
            return throwKeyScheduleError(
                `cipher suite ${cipherSuite} has no AEAD key length — not a negotiable TLS 1.3 suite`,
            );
        default:
            // Every CipherSuite member is covered above; this is unreachable but
            // keeps the switch exhaustive if the union is ever extended.
            return assertNever(cipherSuite);
    }
}

/**
 * Throw a {@link TlsKeyScheduleError} and return `never`, so call sites can use
 * `return throwKeyScheduleError(...)` to satisfy `consistent-return` while failing
 * fast with a descriptive message.
 */
function throwKeyScheduleError(message: string): never {
    throw new TlsKeyScheduleError("SHA-256", message);
}

/** Map a cipher suite to its AEAD IV length in bytes (all TLS 1.3 AEADs use 12). */
export function cipherSuiteIvLength(_cipherSuite: CipherSuite): number {
    return 12;
}

/** Output length (bytes) of the hash used by a cipher suite. */
export function hashLengthFor(hash: HashId): number {
    switch (hash) {
        case "SHA-256":
            return 32;
        case "SHA-384":
            return 48;
        default:
            return assertNever(hash);
    }
}

/** Map a negotiated cipher suite to the hash function used for its transcript. */
export function hashFor(cipherSuite: CipherSuite): HashId {
    return cipherSuiteToHash(cipherSuite);
}

/**
 * HKDF-Extract(salt, Ikm) = HMAC-Hash(salt, Ikm), per RFC 5869 §2.3.
 * The output is exactly {@link hashLengthFor}(hash) bytes.
 */
function hkdfExtract(hash: HashId, salt: Uint8Array, ikm: Uint8Array): Uint8Array {
    // crypto.hmac is declared to return Uint8Array; the cast that used to live
    // here was redundant.
    return crypto.hmac(hash, salt, ikm);
}

/**
 * HKDF-Expand(PRK, info, length) per RFC 5869 §2.3, implemented on top of HMAC
 * because @browsercore/crypto exposes only the combined extract+expand helper.
 */
function hkdfExpand(hash: HashId, prk: Uint8Array, info: Uint8Array, length: number): Uint8Array {
    const hashLen = hashLengthFor(hash);
    const n = Math.ceil(length / hashLen);
    if (n > 255) {
        throw new TlsKeyScheduleError(hash, `HKDF-Expand length ${length} exceeds maximum for hash (255 * ${hashLen})`);
    }
    const okm = new Uint8Array(n * hashLen);
    let t: Uint8Array = new Uint8Array(0);
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
 *
 * Exposed (not just internal) so the handshake layer can derive record
 * protection secrets directly from the raw handshake traffic secrets it needs
 * for the Finished verify-data computation.
 */
export function deriveTrafficSecrets(
    trafficSecret: Uint8Array,
    cipherSuite: CipherSuite,
    hash: HashId,
): TrafficSecrets {
    const key = hkdfExpandLabel(trafficSecret, "key", new Uint8Array(0), cipherSuiteKeyLength(cipherSuite), hash);
    const iv = hkdfExpandLabel(trafficSecret, "iv", new Uint8Array(0), cipherSuiteIvLength(cipherSuite), hash);
    return { key, iv };
}

/**
 * Derive the raw handshake traffic secrets and master secret from the (EC)DHE
 * shared secret and the ClientHello..ServerHello transcript.
 *
 * The raw traffic secrets (one per direction) are the `*-handshake-traffic-
 * secret` values from RFC 8446 §7.1. They are needed to compute the Finished
 * `finished_key` (HKDF-Expand-Label(traffic_secret, "finished", "", Hash.length))
 * and must be retained by the handshake driver — they are NOT the same as the
 * record-protection TrafficSecrets returned by {@link deriveHandshakeSecrets}.
 *
 * @param sharedSecret    (EC)DHE shared secret from @browsercore/crypto.
 * @param helloTranscript Transcript hash of ClientHello..ServerHello.
 * @param cipherSuite     Negotiated cipher suite (selects hash + AEAD sizes).
 */
export function deriveHandshakeTrafficSecrets(
    sharedSecret: Uint8Array,
    helloTranscript: Uint8Array,
    cipherSuite: CipherSuite,
): {
    masterSecret: Uint8Array;
    clientTrafficSecret: Uint8Array;
    serverTrafficSecret: Uint8Array;
} {
    const hash = cipherSuiteToHash(cipherSuite);
    const hashLen = hashLengthFor(hash);
    const zeros = new Uint8Array(hashLen);

    // early_secret = HKDF-Extract(0, 0)
    const earlySecret = hkdfExtract(hash, zeros, zeros);

    // derived = HKDF-Expand-Label(early_secret, "derived", "", Hash.length)
    const derived = hkdfExpandLabel(earlySecret, "derived", new Uint8Array(0), hashLen, hash);

    // handshake_secret = HKDF-Extract(derived, sharedSecret)
    const handshakeSecret = hkdfExtract(hash, derived, sharedSecret);

    // client/server handshake traffic secrets.
    const clientTrafficSecret = hkdfExpandLabel(handshakeSecret, "c hs traffic", helloTranscript, hashLen, hash);
    const serverTrafficSecret = hkdfExpandLabel(handshakeSecret, "s hs traffic", helloTranscript, hashLen, hash);

    // master_secret = HKDF-Extract(Derive-Secret(handshake_secret, "derived", ""), 0)
    const masterDerived = hkdfExpandLabel(handshakeSecret, "derived", new Uint8Array(0), hashLen, hash);
    const masterSecret = hkdfExtract(hash, masterDerived, zeros);

    return { masterSecret, clientTrafficSecret, serverTrafficSecret };
}

/**
 * Derive the handshake record-protection secrets (key + iv per direction) from
 * the (EC)DHE shared secret and the ClientHello..ServerHello transcript.
 *
 * This is the record-layer view of {@link deriveHandshakeTrafficSecrets}: it
 * returns TrafficSecrets ready to pass to the record encrypt/decrypt functions.
 *
 * @param sharedSecret    (EC)DHE shared secret from @browsercore/crypto.
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
    const { masterSecret, clientTrafficSecret, serverTrafficSecret } = deriveHandshakeTrafficSecrets(
        sharedSecret,
        helloTranscript,
        cipherSuite,
    );

    return {
        masterSecret,
        traffic: {
            client: deriveTrafficSecrets(clientTrafficSecret, cipherSuite, hash),
            server: deriveTrafficSecrets(serverTrafficSecret, cipherSuite, hash),
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
    const hashLen = hashLengthFor(hash);

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
    const hashLen = hashLengthFor(hash);
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
