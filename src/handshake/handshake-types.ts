/**
 * TLS handshake message types and shared shapes (RFC 8446 §4).
 *
 * The wire-format constants (HandshakeType) and the structural types every
 * handshake submodule agrees on (ClientHello, ServerHello, HandshakePhase) live
 * here so client-hello.ts (serialization), server-hello.ts (parsing), and
 * state-machine.ts (transitions) can depend on them without creating a cycle
 * through the barrel.
 */

import type { CipherSuite, ProtocolVersion } from "../types.js";

// Re-export the HandshakeType constants + union from a single source. Keeping
// the const object in this module (rather than importing it) means callers have
// one stable path for both the runtime values and the type.
/** TLS handshake message types, per RFC 8446 §4. */
export const HandshakeType = {
    HELLO_REQUEST: 0,
    CLIENT_HELLO: 1,
    SERVER_HELLO: 2,
    NEW_SESSION_TICKET: 4,
    END_OF_EARLY_DATA: 5,
    ENCRYPTED_EXTENSIONS: 8,
    CERTIFICATE: 11,
    SERVER_KEY_EXCHANGE: 12,
    CERTIFICATE_REQUEST: 13,
    SERVER_HELLO_DONE: 14,
    CERTIFICATE_VERIFY: 15,
    CLIENT_KEY_EXCHANGE: 16,
    FINISHED: 20,
    KEY_UPDATE: 24,
    /**
     * RFC 8879 §3 — CompressedCertificate. Sent by a server only when the
     * client advertised the `compress_certificate` extension (ext 27). We never
     * advertise it, so receiving this type signals a non-conformant server or a
     * ClientHello that was modified in transit (e.g. by a CDN).
     */
    COMPRESSED_CERTIFICATE: 25,
    MESSAGE_HASH: 254,
} as const;

/** Union of valid handshake message-type values. */
export type HandshakeType = (typeof HandshakeType)[keyof typeof HandshakeType];

/**
 * A parsed ClientHello (sent by the client, parsed when acting as server — not
 * used client-side but typed for completeness).
 */
export interface ClientHello {
    readonly protocolVersion: number;
    readonly random: Uint8Array;
    readonly sessionId: Uint8Array;
    readonly cipherSuites: readonly number[];
    readonly compressionMethods: readonly number[];
    readonly extensions: Uint8Array;
}

/** A parsed ServerHello — the first handshake message the server sends. */
export interface ServerHello {
    /**
     * Legacy protocol version (always 0x0303 for TLS 1.3, for middlebox
     * compatibility). The real negotiated version is {@link selectedVersion}.
     */
    readonly protocolVersion: number;
    readonly random: Uint8Array;
    readonly sessionId: Uint8Array;
    readonly cipherSuite: CipherSuite;
    readonly compressionMethod: number;
    /**
     * The protocol version the server actually negotiated, extracted from the
     * supported_versions extension. This is the authoritative version.
     */
    readonly selectedVersion: ProtocolVersion;
    readonly extensions: Uint8Array;
}

/**
 * Phases of the client-side handshake state machine. Discriminated union so
 * every transition is exhaustive: adding a phase forces every handler in
 * {@link advanceHandshake} to compile-error until handled.
 */
export type HandshakePhase =
    | { readonly phase: "start" }
    | { readonly phase: "client_hello_sent" }
    | { readonly phase: "server_hello_received"; readonly serverHello: ServerHello }
    | { readonly phase: "encrypted_extensions_received" }
    | { readonly phase: "certificate_received" }
    | { readonly phase: "certificate_verify_received" }
    | { readonly phase: "finished_received" }
    | { readonly phase: "complete" };
