/**
 * Pure-function surface of the connection subsystem.
 *
 * These modules hold every byte-level computation the TLS connection performs —
 * record framing, key exchange, server-flight message handling, and lifecycle
 * bookkeeping. They are written as functions over explicit inputs (the read
 * buffer, traffic secrets, sequence numbers) rather than as methods reaching into
 * private connection state, so the connection class (`../tls.js`) stays a thin
 * coordinator that owns the mutable fields and threads them through.
 *
 * This barrel is the single boundary across which the connection class depends on
 * its internals: tls.ts imports from here, never from the individual modules.
 */

export { ensureOpen, handleAlert, handlePostHandshakeRecord, withTimeout } from "./lifecycle.js";
export { computeSharedSecret, transcriptHash, verifyServerFinished } from "./key-exchange.js";
export {
    buildClientFinishedMessage,
    parseAlpnFromEncryptedExtensions,
    readEncryptedHandshakeMessage,
    validateCertificateChain,
} from "./handshake-messages.js";
export {
    readEncryptedRecord,
    readHeaderBytes,
    readRawRecord,
    writeEncryptedRecord,
    writeRecord,
} from "./record-layer.js";
export { runHandshake, type HandshakeContext } from "./handshake-driver.js";
