/**
 * Tests for @browsercore/tls.
 *
 * Mirrors the transport test style: vitest, real assertions, no mocks for the
 * pure functions (record header parse/serialize). Handshake/crypto parts are
 * stubbed for now — see PLAN.md for the integration steps that fill them in.
 */

import { describe, it, expect } from "vitest";
import {
    ContentType,
    parseRecordHeader,
    serializeRecordHeader,
    cipherSuiteToAead,
    RECORD_HEADER_SIZE,
} from "../src/record/record.js";
import {
    TlsError,
    TlsHandshakeError,
    TlsDecryptError,
    TlsAlertError,
    ensureTlsError,
} from "../src/errors.js";
import { assertNever, createId } from "../src/utils.js";
import { connectTls, TlsConnectionImpl } from "../src/tls.js";

describe("record header", () => {
    it("round-trips serialize -> parse for a handshake record", () => {
        const header = serializeRecordHeader(ContentType.HANDSHAKE, 128, 0x0303);
        expect(header.length).toBe(RECORD_HEADER_SIZE);
        expect(header[0]).toBe(ContentType.HANDSHAKE);

        const parsed = parseRecordHeader(header);
        expect(parsed.type).toBe(ContentType.HANDSHAKE);
        expect(parsed.version).toBe(0x0303);
        expect(parsed.length).toBe(128);
    });

    it("round-trips an application_data record with default version", () => {
        const header = serializeRecordHeader(ContentType.APPLICATION_DATA, 1024);
        const parsed = parseRecordHeader(header);
        expect(parsed.type).toBe(ContentType.APPLICATION_DATA);
        expect(parsed.version).toBe(0x0303);
        expect(parsed.length).toBe(1024);
    });

    it("throws TlsDecryptError when the buffer is too short", () => {
        const buf = new Uint8Array([ContentType.ALERT, 0x03]);
        expect(() => parseRecordHeader(buf)).toThrow(TlsDecryptError);
    });

    it("throws TlsDecryptError for an invalid content type", () => {
        const buf = new Uint8Array([99, 0x03, 0x03, 0x00, 0x10]);
        expect(() => parseRecordHeader(buf)).toThrow(TlsDecryptError);
    });
});

describe("cipher suite helpers", () => {
    it("maps each TLS 1.3 cipher suite to its AEAD algorithm", () => {
        expect(cipherSuiteToAead("TLS_AES_128_GCM_SHA256")).toBe("AES-128-GCM");
        expect(cipherSuiteToAead("TLS_AES_256_GCM_SHA384")).toBe("AES-256-GCM");
        expect(cipherSuiteToAead("TLS_CHACHA20_POLY1305_SHA256")).toBe("CHACHA20-POLY1305");
        expect(cipherSuiteToAead("TLS_AES_128_CCM_SHA256")).toBe("AES-128-GCM");
    });
});

describe("typed errors", () => {
    it("instantiates TlsError with details and cause", () => {
        const cause = new Error("boom");
        const err = new TlsError("something failed", { foo: 1 }, { cause });
        expect(err).toBeInstanceOf(Error);
        expect(err.kind).toBe("TlsError");
        expect(err.details.foo).toBe(1);
        expect(err.cause).toBe(cause);
        expect(err.name).toBe("TlsError");
    });

    it("TlsHandshakeError carries its phase", () => {
        const err = new TlsHandshakeError("server_hello");
        expect(err.kind).toBe("TlsHandshakeError");
        expect(err.phase).toBe("server_hello");
        expect(err.message).toContain("server_hello");
    });

    it("TlsDecryptError carries its algorithm", () => {
        const err = new TlsDecryptError("AES-128-GCM");
        expect(err.kind).toBe("TlsDecryptError");
        expect(err.algorithm).toBe("AES-128-GCM");
    });

    it("TlsAlertError carries level and description", () => {
        const err = new TlsAlertError("fatal", 40);
        expect(err.kind).toBe("TlsAlertError");
        expect(err.level).toBe("fatal");
        expect(err.description).toBe(40);
    });

    it("ensureTlsError wraps unknown values", () => {
        expect(ensureTlsError(new TlsError("x"))).toBeInstanceOf(TlsError);
        expect(ensureTlsError(new Error("y"))).toBeInstanceOf(TlsError);
        expect(ensureTlsError("z")).toBeInstanceOf(TlsError);
        expect(ensureTlsError(undefined)).toBeInstanceOf(TlsError);
    });
});

describe("utils", () => {
    it("createId generates unique prefixed ids", () => {
        const a = createId("tls");
        const b = createId("tls");
        expect(a).toMatch(/^tls_/);
        expect(a).not.toBe(b);
    });

    it("assertNever throws on use", () => {
        expect(() => assertNever(undefined as never)).toThrow();
    });
});

describe("public API surface", () => {
    it("connectTls exists and is callable", () => {
        expect(typeof connectTls).toBe("function");
    });

    it.todo("connectTls performs the TLS 1.3 handshake and returns a live TlsConnection (see PLAN.md)");

    it("TlsConnectionImpl exposes a branded id and starts connecting", () => {
        const conn = new TlsConnectionImpl();
        expect(conn.id).toMatch(/^tls_/);
        expect(conn.state.state).toBe("connecting");
        expect(conn.protocolVersion.name).toBe("TLS 1.3");
        expect(conn.cipherSuite).toBe("TLS_AES_128_GCM_SHA256");
    });
});
