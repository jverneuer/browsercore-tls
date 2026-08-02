/**
 * @browsercore/tls — public API surface.
 *
 * A TLS 1.3 (and 1.2 fallback) client implemented entirely in TypeScript.
 * Depends on @browsercore/transport and @browsercore/crypto — never node:crypto directly.
 * Higher layers (http1, http2, fetch) compose exclusively through these exports.
 */

export { connectTls, TlsConnectionImpl, generateKeyShares } from "./tls.js";
export type { TlsConnection } from "./types.js";

export {
    TlsError,
    TlsHandshakeError,
    TlsDecryptError,
    TlsAlertError,
    ensureTlsError,
} from "./errors.js";
export type { HandshakePhase, AlertLevel } from "./errors.js";

export {
    type ApplicationData,
    type ApplicationTrafficSecrets,
    type CipherSuite,
    type ClientHelloConfig,
    type CloseReason,
    type KeyPair,
    type NamedGroup,
    type ProtocolVersion,
    type SignatureScheme,
    type TlsOptions,
    type TlsSessionId,
    type TlsState,
    type TrafficSecrets,
    TLS_1_2,
    TLS_1_3,
} from "./types.js";

export { type TlsProfile, MODERN_TLS13_PROFILE, COMPATIBILITY_PROFILE, getProfile, resolveProfile } from "./profiles/profiles.js";

export {
    ContentType,
    parseRecordHeader,
    serializeRecordHeader,
    cipherSuiteToAead,
    RECORD_HEADER_SIZE,
} from "./record/record.js";
export type { ContentType as TlsContentType, RecordHeader, TlsRecord } from "./record/record.js";

export { HandshakeType, buildClientHello, parseServerHello } from "./handshake/handshake.js";
export type {
    ClientHello,
    ServerHello,
    ServerHelloValidation,
    HandshakeType as TlsHandshakeType,
} from "./handshake/handshake.js";

export { ExtensionType, parseExtensions, findExtension, wireToNamedGroup } from "./extensions/extensions.js";
export type { TlsExtension } from "./extensions/extensions.js";

export { parseCertificate, validateHostname, verifyChain, pemToDer } from "./certificates/certificates.js";
export type { Certificate, CertificateChain, TrustAnchor } from "./certificates/certificates.js";

export {
    hkdfExpandLabel,
    deriveHandshakeSecrets,
    deriveHandshakeTrafficSecrets,
    deriveApplicationSecrets,
} from "./crypto/keySchedule.js";

export { assertNever } from "./utils.js";
