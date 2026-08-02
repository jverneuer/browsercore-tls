/**
 * Domain types for @network/tls.
 *
 * This package owns TLS 1.3 (and 1.2 fallback) protocol logic. It knows about
 * byte streams (@network/transport) and cryptographic primitives (@network/crypto)
 * but NEVER imports node:crypto directly — that boundary is @network/crypto's job.
 */

import type { Transport } from "@network/transport";
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
    | "CHACHA20-POLY1305";

/** A TLS 1.3 cipher suite (AEAD + hash). String-literal union — never bare string. */
export type CipherSuite =
    | "TLS_AES_128_GCM_SHA256"
    | "TLS_AES_256_GCM_SHA384"
    | "TLS_CHACHA20_POLY1305_SHA256"
    | "TLS_AES_128_CCM_SHA256";

/** Named groups for key share (ECDHE). */
export type NamedGroup =
    | "secp256r1"
    | "secp384r1"
    | "x25519"
    | "x448";

/** Signature algorithms for certificate verification. */
export type SignatureScheme =
    | "ecdsa_secp256r1_sha256"
    | "ecdsa_secp384r1_sha384"
    | "rsa_pss_rsae_sha256"
    | "rsa_pss_rsae_sha384"
    | "rsa_pkcs1_sha256";

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

/** Configuration for building a ClientHello. Placeholder until @network/profiles. */
export interface ClientHelloConfig {
    /** Ordered list of cipher suites the client advertises (most-preferred first). */
    readonly cipherSuites: readonly CipherSuite[];
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
}

/** Public options for {@link connectTls}. */
export interface TlsOptions {
    /** The underlying byte-stream transport (already connected or connecting). */
    readonly transport: Transport;
    /** SNI server name. Defaults to host if omitted. */
    readonly serverName: string;
    /** ClientHello configuration (placeholder until @network/profiles is built). */
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
 * generates them — it asks @network/crypto.
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
