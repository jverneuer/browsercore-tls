/**
 * Tests for @browsercore/tls ServerHello parsing (RFC 8446 §4.2.1).
 *
 * The handshake.test.ts file only exercises parseServerHello's error branches
 * (unknown cipher suite, missing/unsupported-length supported_versions). This
 * file covers the rest: the happy path (a fully valid ServerHello round-trips
 * into a typed ServerHello), the expect() truncation guard, the non-null
 * compression-method rejection, and the selectVersion "version we did not
 * offer" branch.
 */

import { describe, it, expect } from "vitest";
import { parseServerHello, type ServerHelloValidation } from "../src/handshake/server-hello.js";
import { TlsHandshakeError } from "../src/errors.js";
import { ExtensionType } from "../src/extensions/extensions.js";
import { TLS_1_3 } from "../src/types.js";

const OFFERED: ServerHelloValidation = {
    cipherSuites: ["TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"],
    supportedVersions: [TLS_1_3],
};

/**
 * Build a (possibly corrupt) ServerHello body from its logical fields so the
 * tests read in terms of intent rather than magic offsets. The body is the
 * handshake message body WITHOUT the 4-byte handshake header — exactly what
 * parseServerHello expects.
 *
 * @param cipherSuite 2-byte IANA wire value (default TLS_AES_128_GCM_SHA256).
 * @param compression compression-method byte (default 0x00).
 * @param sessionId   session-id bytes (default empty).
 * @param versionWire 2-byte version the server selects (default TLS 1.3).
 */
function buildServerHelloBody(opts: {
    cipherSuite?: number;
    compression?: number;
    sessionId?: Uint8Array;
    versionWire?: number;
    /** Override the 32-byte random field (default: 32 bytes of 0x5a). */
    random?: Uint8Array;
} = {}): Uint8Array {
    const random = opts.random ?? new Uint8Array(32).fill(0x5a);
    const sessionId = opts.sessionId ?? new Uint8Array(0);
    const cipherSuite = opts.cipherSuite ?? 0x1301;
    const compression = opts.compression ?? 0x00;
    const versionWire = opts.versionWire ?? TLS_1_3.wire;

    // supported_versions extension body: a single uint16 — the selected version.
    const svData = new Uint8Array([(versionWire >> 8) & 0xff, versionWire & 0xff]);
    const svExt = new Uint8Array(2 + 2 + svData.length);
    svExt[0] = (ExtensionType.SUPPORTED_VERSIONS >> 8) & 0xff;
    svExt[1] = ExtensionType.SUPPORTED_VERSIONS & 0xff;
    svExt[2] = (svData.length >> 8) & 0xff;
    svExt[3] = svData.length & 0xff;
    svExt.set(svData, 4);

    const body = new Uint8Array(2 + 32 + 1 + sessionId.length + 2 + 1 + 2 + svExt.length);
    let o = 0;
    body[o++] = 0x03; // legacy_version = TLS 1.2
    body[o++] = 0x03;
    body.set(random, o);
    o += 32;
    body[o++] = sessionId.length;
    body.set(sessionId, o);
    o += sessionId.length;
    body[o++] = (cipherSuite >> 8) & 0xff;
    body[o++] = cipherSuite & 0xff;
    body[o++] = compression;
    body[o++] = (svExt.length >> 8) & 0xff;
    body[o++] = svExt.length & 0xff;
    body.set(svExt, o);
    return body;
}

describe("parseServerHello happy path", () => {
    it("parses a fully valid ServerHello into a typed ServerHello", () => {
        const body = buildServerHelloBody();
        const hello = parseServerHello(body, OFFERED);

        expect(hello.protocolVersion).toBe(0x0303);
        expect(hello.random).toHaveLength(32);
        expect(hello.sessionId).toEqual(new Uint8Array(0));
        expect(hello.cipherSuite).toBe("TLS_AES_128_GCM_SHA256");
        expect(hello.compressionMethod).toBe(0x00);
        expect(hello.selectedVersion).toBe(TLS_1_3);
        // extensions slice retains the 2-byte length prefix (it is the raw block).
        expect(hello.extensions.length).toBeGreaterThan(2);
    });

    it("parses a ServerHello that negotiates AES-256-GCM", () => {
        const body = buildServerHelloBody({ cipherSuite: 0x1302 });
        const hello = parseServerHello(body, OFFERED);
        expect(hello.cipherSuite).toBe("TLS_AES_256_GCM_SHA384");
    });

    it("parses a ServerHello carrying a session id", () => {
        const sessionId = new Uint8Array([0x01, 0x02, 0x03, 0x04]);
        const body = buildServerHelloBody({ sessionId });
        const hello = parseServerHello(body, OFFERED);
        expect(hello.sessionId).toEqual(sessionId);
    });
});

describe("parseServerHello truncation guard (expect)", () => {
    it("throws TlsHandshakeError when the body is truncated before the fixed prefix", () => {
        // The very first expect() guards 2 (version) + 32 (random) + 1 (sid len).
        const body = new Uint8Array(2 + 32); // missing the session-id length byte
        try {
            parseServerHello(body, OFFERED);
            expect.unreachable("expected a throw");
        } catch (e) {
            const err = e as TlsHandshakeError;
            expect(err).toBeInstanceOf(TlsHandshakeError);
            expect(err.phase).toBe("server_hello");
            expect(err.cause?.message).toMatch(/truncated/);
        }
    });

    it("throws when the session-id length byte claims more bytes than are present", () => {
        // version(2) + random(32) + sid_len=5, but no session-id bytes follow.
        const body = new Uint8Array(2 + 32 + 1);
        body[2 + 32] = 5;
        try {
            parseServerHello(body, OFFERED);
            expect.unreachable("expected a throw");
        } catch (e) {
            const err = e as TlsHandshakeError;
            expect(err.cause?.message).toMatch(/truncated/);
        }
    });
});

describe("parseServerHello compression method", () => {
    it("rejects a non-null compression method", () => {
        // TLS 1.3 forbids compression — the only legal value is 0x00.
        const body = buildServerHelloBody({ compression: 0x01 });
        try {
            parseServerHello(body, OFFERED);
            expect.unreachable("expected a throw");
        } catch (e) {
            const err = e as TlsHandshakeError;
            expect(err).toBeInstanceOf(TlsHandshakeError);
            expect(err.cause?.message).toMatch(/unsupported compression method/);
        }
    });
});

describe("selectVersion (server negotiates a version we did not offer)", () => {
    it("throws when the server selects a version absent from offered.supportedVersions", () => {
        // Server selects TLS 1.2 (0x0303) but the client only offered TLS 1.3.
        const body = buildServerHelloBody({ versionWire: 0x0303 });
        try {
            parseServerHello(body, OFFERED);
            expect.unreachable("expected a throw");
        } catch (e) {
            const err = e as TlsHandshakeError;
            expect(err).toBeInstanceOf(TlsHandshakeError);
            expect(err.cause?.message).toMatch(/server negotiated version we did not offer/);
        }
    });
});

// ---------------------------------------------------------------------------
// Downgrade protection sentinels (RFC 8446 §4.1.3)
// ---------------------------------------------------------------------------

describe("parseServerHello downgrade protection", () => {
    it("rejects a TLS 1.2 downgrade sentinel in the last 8 bytes of random", () => {
        // DOWNGRD\x01 = 44 4F 57 4E 47 52 44 01
        const random = new Uint8Array(32).fill(0x5a);
        random.set([0x44, 0x4f, 0x57, 0x4e, 0x47, 0x52, 0x44, 0x01], 24);
        const body = buildServerHelloBody({ random });

        try {
            parseServerHello(body, OFFERED);
            expect.unreachable("expected a throw");
        } catch (e) {
            const err = e as TlsHandshakeError;
            expect(err).toBeInstanceOf(TlsHandshakeError);
            expect(err.phase).toBe("server_hello");
            expect(err.cause?.message).toMatch(/downgrade sentinel/);
        }
    });

    it("rejects a TLS 1.1-or-below downgrade sentinel in the last 8 bytes of random", () => {
        // DOWNGRD\x00 = 44 4F 57 4E 47 52 44 00
        const random = new Uint8Array(32).fill(0x5a);
        random.set([0x44, 0x4f, 0x57, 0x4e, 0x47, 0x52, 0x44, 0x00], 24);
        const body = buildServerHelloBody({ random });

        try {
            parseServerHello(body, OFFERED);
            expect.unreachable("expected a throw");
        } catch (e) {
            const err = e as TlsHandshakeError;
            expect(err.cause?.message).toMatch(/downgrade sentinel/);
        }
    });

    it("accepts a normal ServerHello whose last 8 bytes are not a sentinel", () => {
        // The default 0x5a fill does not match either sentinel — must succeed.
        const body = buildServerHelloBody();
        const hello = parseServerHello(body, OFFERED);
        expect(hello.selectedVersion).toBe(TLS_1_3);
    });

    it("accepts a random field whose tail coincidentally starts with DOWNGRD but is not a sentinel", () => {
        // 44 4F 57 4E 47 52 44 02 — shares the prefix but the last byte differs.
        const random = new Uint8Array(32).fill(0x5a);
        random.set([0x44, 0x4f, 0x57, 0x4e, 0x47, 0x52, 0x44, 0x02], 24);
        const body = buildServerHelloBody({ random });
        const hello = parseServerHello(body, OFFERED);
        expect(hello.selectedVersion).toBe(TLS_1_3);
    });
});
