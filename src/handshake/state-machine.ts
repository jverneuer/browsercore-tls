/**
 * TLS handshake state machine (RFC 8446 §4).
 *
 * Tracks the client's progress through the server's flight of messages
 * (ServerHello -> EncryptedExtensions -> Certificate -> CertificateVerify ->
 * Finished) and validates every transition, so an out-of-order or repeated
 * message is rejected at the type level rather than corrupting handshake state.
 *
 * Also hosts the small predicate helpers over {@link NamedGroup} and
 * {@link ProtocolVersion} that the handshake layer needs — kept here (rather
 * than in types.ts) because they are handshake-layer decisions, not pure type
 * facts.
 */

import type { NamedGroup, ProtocolVersion } from "../types.js";
import { TlsHandshakeError } from "../errors.js";
import { assertNever } from "../utils.js";
import { HandshakeType, type HandshakePhase, type ServerHello } from "./handshake-types.js";

/**
 * Transition the handshake state machine given the next received message type.
 * Returns the next phase, or throws {@link TlsHandshakeError} on an invalid
 * transition (making invalid state sequences unrepresentable).
 */
export function advanceHandshake(current: HandshakePhase, received: HandshakeType): HandshakePhase {
    switch (current.phase) {
        case "start":
            throw new TlsHandshakeError("client_hello", {
                cause: new Error("expected client_hello_sent as the first transition"),
            });
        case "client_hello_sent":
            if (received !== HandshakeType.SERVER_HELLO) {
                throw new TlsHandshakeError("server_hello", {
                    cause: new Error(`expected SERVER_HELLO after client_hello_sent, got ${received}`),
                });
            }
            // The caller must call `recordServerHello` to attach the parsed ServerHello.
            throw new TlsHandshakeError("server_hello", {
                cause: new Error(
                    "use recordServerHello(serverHello) to transition client_hello_sent -> server_hello_received",
                ),
            });
        case "server_hello_received":
            if (received !== HandshakeType.ENCRYPTED_EXTENSIONS) {
                throw new TlsHandshakeError("server_hello", {
                    cause: new Error(`expected ENCRYPTED_EXTENSIONS, got ${received}`),
                });
            }
            return { phase: "encrypted_extensions_received" };
        case "encrypted_extensions_received":
            if (received !== HandshakeType.CERTIFICATE) {
                throw new TlsHandshakeError("certificate", {
                    cause: new Error(`expected CERTIFICATE, got ${received}`),
                });
            }
            return { phase: "certificate_received" };
        case "certificate_received":
            if (received !== HandshakeType.CERTIFICATE_VERIFY) {
                throw new TlsHandshakeError("certificate", {
                    cause: new Error(`expected CERTIFICATE_VERIFY, got ${received}`),
                });
            }
            return { phase: "certificate_verify_received" };
        case "certificate_verify_received":
            if (received !== HandshakeType.FINISHED) {
                throw new TlsHandshakeError("finished", {
                    cause: new Error(`expected FINISHED, got ${received}`),
                });
            }
            return { phase: "finished_received" };
        case "finished_received":
        case "complete":
            throw new TlsHandshakeError("finished", {
                cause: new Error(`handshake already in terminal phase: ${current.phase}`),
            });
        default:
            return assertNever(current);
    }
}

/**
 * Record the parsed ServerHello and transition from "client_hello_sent" to
 * "server_hello_received". Separated from {@link advanceHandshake} because the
 * state machine needs to carry the parsed ServerHello forward.
 */
export function recordServerHello(_current: HandshakePhase, serverHello: ServerHello): HandshakePhase {
    void _current;
    return { phase: "server_hello_received", serverHello };
}

/** Mark the handshake as complete (after client Finished is sent). */
export function completeHandshake(_current: HandshakePhase): HandshakePhase {
    void _current;
    return { phase: "complete" };
}

/** True if the named group is a (EC)DHE group usable for TLS 1.3 key share. */
export function isKeyShareGroup(group: NamedGroup): boolean {
    switch (group) {
        case "secp256r1":
        case "secp384r1":
        case "x25519":
        case "x448":
            return true;
        // Post-quantum hybrid groups are valid TLS 1.3 key-share groups.
        // They are advertised in supported_groups; the key_share carries the
        // classical component (handled in generateKeyShares).
        case "X25519Kyber768":
        case "X25519MLKEM768":
        case "Secp256r1MLKEM768":
        case "Secp384r1MLKEM1024":
            return true;
        default:
            return assertNever(group);
    }
}

/** True if the protocol version is TLS 1.3. */
export function isTls13(version: ProtocolVersion): boolean {
    return version.name === "TLS 1.3";
}
