/**
 * Domain types for @browsercore/tls.
 *
 * This package owns TLS 1.3 (and 1.2 fallback) protocol logic. It knows about
 * byte streams (@browsercore/transport) and cryptographic primitives (@browsercore/crypto)
 * but NEVER imports node:crypto directly — that boundary is @browsercore/crypto's job.
 */

import type { Transport } from "@browsercore/transport";
import type { TlsError } from "./errors.js";

/** Branded TLS session identifier. */
export type TlsSessionId = string & { __brand: "TlsSessionId" };

/**
 * TLS protocol versions. Wire values follow RFC 8446 / RFC 5246:
 * TLS 1.2 = 0x0303, TLS 1.3 = 0x0304.
 */
export type ProtocolVersion =
    | { readonly name: "TLS 1.2"; readonly wire: 0x0303 }
    | { readonly name: "TLS 1.3"; readonly wire: 0x0304 };

/** TLS 1.2 protocol version constant. */
export const TLS_1_2: ProtocolVersion = { name: "TLS 1.2", wire: 0x0303 } as const;

/** TLS 1.3 protocol version constant. */
export const TLS_1_3: ProtocolVersion = { name: "TLS 1.3", wire: 0x0304 } as const;

/** AEAD algorithms used by TLS record protection. */
export type AeadAlgorithm =
    | "AES-128-GCM"
    | "AES-256-GCM"
    | "AES-128-CCM"
    | "CHACHA20-POLY1305";

/**
 * A TLS cipher suite. String-literal union — never bare string.
 *
 * This union covers every suite the shipped browser profiles offer: the four
 * TLS 1.3 AEAD suites (the only ones a TLS 1.3 handshake can *negotiate*) plus
 * the TLS 1.2 suites and the GREASE placeholder that real browsers place in the
 * *offered* ClientHello list for middlebox compatibility. The negotiated suite
 * is always one of the four AEAD suites; the TLS 1.2 names only ever appear in
 * the offered list.
 */
export type CipherSuite =
    | "TLS_GREASE_RESERVED_0"
    | "TLS_AES_128_GCM_SHA256"
    | "TLS_AES_256_GCM_SHA384"
    | "TLS_CHACHA20_POLY1305_SHA256"
    | "TLS_AES_128_CCM_SHA256"
    | "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
    | "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
    | "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
    | "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
    | "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"
    | "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
    | "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"
    | "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"
    | "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"
    | "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"
    | "TLS_RSA_WITH_AES_128_GCM_SHA256"
    | "TLS_RSA_WITH_AES_256_GCM_SHA384"
    | "TLS_RSA_WITH_AES_128_CBC_SHA"
    | "TLS_RSA_WITH_AES_256_CBC_SHA";

/** Named groups for key share (ECDHE). */
export type NamedGroup =
    | "secp256r1"
    | "secp384r1"
    | "x25519"
    | "x448"
    // Post-quantum hybrid key share groups (draft-ietf-tls-hybrid-design).
    // X25519Kyber768 and X25519MLKEM768 have assigned IANA codes; the two
    // MLKEM groups below are not yet standardized — they live in the union
    // for forward-compat but are handled classically on the wire (hybrid
    // mode: advertised in supported_groups, key_share carries the classical
    // X25519/secp256r1 component — matching real Chrome behavior).
    | "X25519Kyber768"
    | "X25519MLKEM768"
    | "Secp256r1MLKEM768"
    | "Secp384r1MLKEM1024";

/**
 * Signature algorithms for certificate verification.
 *
 * Covers every scheme the shipped browser profiles offer (chrome-140,
 * firefox-128). The negotiated scheme is validated against this list by the
 * server; offering the real-browser set is what makes the fingerprint pass.
 */
export type SignatureScheme =
    | "ecdsa_secp256r1_sha256"
    | "ecdsa_secp384r1_sha384"
    | "ed25519"
    | "rsa_pss_rsae_sha256"
    | "rsa_pss_rsae_sha384"
    | "rsa_pss_rsae_sha512"
    | "rsa_pkcs1_sha256"
    | "rsa_pkcs1_sha384"
    | "rsa_pkcs1_sha512"
    | "rsa_pkcs1_sha1";

/** Why a TLS connection was closed. Discriminated union — every case is explicit. */
export type CloseReason =
    | { readonly kind: "close_notify"; readonly alert?: number }
    | { readonly kind: "error"; readonly error: TlsError }
    | { readonly kind: "transport_closed" }
    | { readonly kind: "timeout"; readonly afterMs: number };

/**
 * Lifecycle state of a TLS connection.
 *
 * `open` carries the negotiated parameters so they can be observed without
 * re-deriving them. `closed` carries the reason for observability.
 */
export type TlsState =
    | { readonly state: "connecting" }
    | { readonly state: "handshaking" }
    | {
        readonly state: "open";
        readonly sessionId: TlsSessionId;
        readonly protocolVersion: ProtocolVersion;
        readonly cipherSuite: CipherSuite;
        readonly alpnProtocol?: string;
    }
    | { readonly state: "closed"; readonly reason: CloseReason };

/**
 * Configuration for building a ClientHello.
 *
 * Driven by a browser profile: the offered cipher suites, the exact extension
 * order, the GREASE flag, key-share groups, signature algorithms, supported
 * versions, SNI, and ALPN. Higher layers (fetch) translate a `BrowserProfile`
 * into this shape.
 */
export interface ClientHelloConfig {
    /** Ordered list of cipher suites the client advertises (most-preferred first). */
    readonly cipherSuites: readonly CipherSuite[];
    /**
     * Extension types in the exact order they must appear in the ClientHello.
     * Every type present here is emitted; anything absent is omitted. This is
     * the primary fingerprinting signal, so the order is load-bearing.
     */
    readonly extensionOrder: readonly number[];
    /** Named groups for key share, ordered by preference. */
    readonly keyShareGroups: readonly NamedGroup[];
    /** Signature algorithms the client accepts in CertificateVerify. */
    readonly signatureAlgorithms: readonly SignatureScheme[];
    /** Protocol versions the client advertises via supported_versions. */
    readonly supportedVersions: readonly ProtocolVersion[];
    /** Server Name Indication hostname (SNI). */
    readonly serverName: string;
    /** ALPN protocols the client wishes to negotiate (e.g. "h2", "http/1.1"). */
    readonly alpnProtocols?: readonly string[];
    /**
     * Whether to inject GREASE (RFC 8701) sentinel values: a GREASE cipher suite
     * at the front of the list, a GREASE extension, and a GREASE key-share
     * group. Real Chrome sets this; real Firefox does not.
     */
    readonly grease: boolean;
}

/** Public options for {@link connectTls}. */
export interface TlsOptions {
    /** The underlying byte-stream transport (already connected or connecting). */
    readonly transport: Transport;
    /** SNI server name. Defaults to host if omitted. */
    readonly serverName: string;
    /** ClientHello configuration (placeholder until @browsercore/profiles is built). */
    readonly profile: ClientHelloConfig;
    /** ALPN protocols to offer. Overrides profile.alpnProtocols if provided. */
    readonly alpnProtocols?: readonly string[];
    /** Connect + handshake timeout in milliseconds. Default 10_000. */
    readonly handshakeTimeoutMs?: number;
    /** Trust anchors (PEM or DER) for certificate verification. Defaults to system roots. */
    readonly trustAnchors?: readonly Uint8Array[];
}

/**
 * An asymmetric key pair. Bytes are algorithm-specific; this package never
 * generates them — it asks @browsercore/crypto.
 */
export interface KeyPair {
    readonly algorithm: "x25519" | "secp256r1" | "secp384r1";
    /** Private key bytes (opaque to this package). */
    readonly privateKey: Uint8Array;
    /** Public key bytes, as would appear in a KeyShareEntry. */
    readonly publicKey: Uint8Array;
}

/** Traffic secrets derived by the TLS 1.3 key schedule for one direction. */
export interface TrafficSecrets {
    /** AEAD key for this direction. */
    readonly key: Uint8Array;
    /** AEAD IV (often called "write_iv") for this direction. */
    readonly iv: Uint8Array;
}

/** Full set of traffic secrets for both directions after the handshake. */
export interface ApplicationTrafficSecrets {
    readonly client: TrafficSecrets;
    readonly server: TrafficSecrets;
}

/** Application-data payload, decrypted and ready for the higher layer. */
export interface ApplicationData {
    readonly payload: Uint8Array;
}

/** The public interface for an established TLS connection. */
export interface TlsConnection {
    /** Opaque session identifier for logging / correlation. */
    readonly id: TlsSessionId;
    /** Current lifecycle state. */
    readonly state: TlsState;
    /** Negotiated protocol version (available once open). */
    readonly protocolVersion: ProtocolVersion;
    /** Negotiated cipher suite (available once open). */
    readonly cipherSuite: CipherSuite;
    /** ALPN protocol the server selected, if any. */
    readonly alpnProtocol?: string;

    /**
     * Read the next decrypted application-data record. Resolves with the payload,
     * or rejects if the connection closes before a complete record arrives.
     */
    read(): Promise<ApplicationData>;

    /**
     * Encrypt and write application data. Resolves when the record has been
     * handed to the transport. Rejects if the connection is not open.
     */
    write(data: Uint8Array): Promise<void>;

    /**
     * Send close_notify and close the underlying transport. Resolves once the
     * connection reaches the `closed` terminal state. Idempotent.
     */
    close(): Promise<void>;

    /** Subscribe to lifecycle events (close / error) for observability. */
    on(event: "close" | "error", listener: (arg: CloseReason | TlsError) => void): this;
}
