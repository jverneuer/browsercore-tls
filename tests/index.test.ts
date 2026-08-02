/**
 * Tests for the @browsercore/tls public barrel (index.ts).
 *
 * index.ts is a pure re-export surface — importing it exercises every `export`
 * statement. We assert the full public API is reachable through the barrel so a
 * regression that drops an export is caught.
 */

import { describe, it, expect } from "vitest";
import {
    connectTls,
    TlsConnectionImpl,
    generateKeyShares,
    TlsError,
    TlsHandshakeError,
    TlsDecryptError,
    TlsAlertError,
    ensureTlsError,
    ContentType,
    parseRecordHeader,
    serializeRecordHeader,
    cipherSuiteToAead,
    RECORD_HEADER_SIZE,
    HandshakeType,
    buildClientHello,
    parseServerHello,
    ExtensionType,
    parseExtensions,
    findExtension,
    wireToNamedGroup,
    parseCertificate,
    validateHostname,
    verifyChain,
    pemToDer,
    hkdfExpandLabel,
    deriveHandshakeSecrets,
    deriveHandshakeTrafficSecrets,
    deriveApplicationSecrets,
    assertNever,
} from "../src/index.js";
import type {
    TlsConnection,
    ApplicationData,
    ApplicationTrafficSecrets,
    CipherSuite,
    ClientHelloConfig,
    CloseReason,
    KeyPair,
    NamedGroup,
    ProtocolVersion,
    SignatureScheme,
    TlsOptions,
    TlsSessionId,
    TlsState,
    TrafficSecrets,
} from "../src/index.js";
import type { TlsContentType, RecordHeader, TlsRecord } from "../src/index.js";
import type {
    ClientHello,
    ServerHello,
    ServerHelloValidation,
} from "../src/index.js";
import type { TlsExtension } from "../src/index.js";
import type { Certificate, CertificateChain, TrustAnchor } from "../src/index.js";
import type { TlsProfile } from "../src/index.js";
import type { HandshakePhase, AlertLevel } from "../src/index.js";

describe("barrel re-exports (values)", () => {
    it("re-exports the public functions", () => {
        expect(typeof connectTls).toBe("function");
        expect(typeof TlsConnectionImpl).toBe("function");
        expect(typeof generateKeyShares).toBe("function");
        expect(typeof ensureTlsError).toBe("function");
        expect(typeof assertNever).toBe("function");
    });

    it("re-exports the error classes", () => {
        expect(TlsError).toBeInstanceOf(Function);
        expect(TlsHandshakeError).toBeInstanceOf(Function);
        expect(TlsDecryptError).toBeInstanceOf(Function);
        expect(TlsAlertError).toBeInstanceOf(Function);
    });

    it("re-exports the record-layer API", () => {
        expect(ContentType.HANDSHAKE).toBe(22);
        expect(typeof parseRecordHeader).toBe("function");
        expect(typeof serializeRecordHeader).toBe("function");
        expect(typeof cipherSuiteToAead).toBe("function");
        expect(RECORD_HEADER_SIZE).toBe(5);
    });

    it("re-exports the handshake API", () => {
        expect(HandshakeType.CLIENT_HELLO).toBe(1);
        expect(typeof buildClientHello).toBe("function");
        expect(typeof parseServerHello).toBe("function");
    });

    it("re-exports the extensions API", () => {
        expect(ExtensionType.KEY_SHARE).toBe(51);
        expect(typeof parseExtensions).toBe("function");
        expect(typeof findExtension).toBe("function");
        expect(typeof wireToNamedGroup).toBe("function");
    });

    it("re-exports the certificates API", () => {
        expect(typeof parseCertificate).toBe("function");
        expect(typeof validateHostname).toBe("function");
        expect(typeof verifyChain).toBe("function");
        expect(typeof pemToDer).toBe("function");
    });

    it("re-exports the key-schedule API", () => {
        expect(typeof hkdfExpandLabel).toBe("function");
        expect(typeof deriveHandshakeSecrets).toBe("function");
        expect(typeof deriveHandshakeTrafficSecrets).toBe("function");
        expect(typeof deriveApplicationSecrets).toBe("function");
    });
});

// Type-only imports are erased at compile time, but referencing them in a typed
// position confirms the barrel actually declares them (a missing one is a
// compile error, not a runtime failure).
describe("barrel re-exports (types)", () => {
    it("declares the public type surface", () => {
        const types: Record<string, unknown> = {};
        // Touch each type name so a missing export breaks the build.
        types.conn = null as unknown as TlsConnection;
        types.ad = null as unknown as ApplicationData;
        types.ats = null as unknown as ApplicationTrafficSecrets;
        types.cs = null as unknown as CipherSuite;
        types.chc = null as unknown as ClientHelloConfig;
        types.cr = null as unknown as CloseReason;
        types.kp = null as unknown as KeyPair;
        types.ng = null as unknown as NamedGroup;
        types.pv = null as unknown as ProtocolVersion;
        types.ss = null as unknown as SignatureScheme;
        types.opts = null as unknown as TlsOptions;
        types.sid = null as unknown as TlsSessionId;
        types.state = null as unknown as TlsState;
        types.ts = null as unknown as TrafficSecrets;
        types.ct = null as unknown as TlsContentType;
        types.rh = null as unknown as RecordHeader;
        types.tr = null as unknown as TlsRecord;
        types.ch = null as unknown as ClientHello;
        types.sh = null as unknown as ServerHello;
        types.shv = null as unknown as ServerHelloValidation;
        types.ext = null as unknown as TlsExtension;
        types.cert = null as unknown as Certificate;
        types.chain = null as unknown as CertificateChain;
        types.ta = null as unknown as TrustAnchor;
        types.profile = null as unknown as TlsProfile;
        types.hp = null as unknown as HandshakePhase;
        types.al = null as unknown as AlertLevel;
        expect(Object.keys(types).length).toBeGreaterThan(0);
    });
});
