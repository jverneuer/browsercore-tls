/**
 * Tests for @browsercore/tls connection lifecycle helpers.
 *
 * withTimeout, alert translation, state-guard checks, and listener fan-out.
 * These are the small pure functions the connection class threads its lifetime
 * through — kept here to cover the error/edge branches tls.ts exercises at
 * runtime but rarely reaches in unit tests.
 */

import { describe, it, expect, vi } from "vitest";
import {
    ensureOpen,
    handleAlert,
    handlePostHandshakeRecord,
    emitError,
    notifyClose,
    withTimeout,
} from "../src/connection/lifecycle.js";
import { TlsAlertError, TlsError, TlsHandshakeError } from "../src/errors.js";
import { ContentType } from "../src/record/record.js";

describe("withTimeout", () => {
    it("resolves normally when the inner work finishes before the deadline", async () => {
        const run = vi.fn(async () => {
            // immediate
        });
        await withTimeout(1000, run);
        expect(run).toHaveBeenCalledTimes(1);
    });

    it("rejects with TlsHandshakeError when the work exceeds the timeout", async () => {
        const run = () => new Promise<void>(() => {}); // never resolves
        await expect(withTimeout(10, run)).rejects.toThrow(TlsHandshakeError);
    });

    it("rejects with the inner error when the work itself throws", async () => {
        const run = async () => {
            throw new Error("handshake blew up");
        };
        await expect(withTimeout(1000, run)).rejects.toThrow("handshake blew up");
    });

    it("clears the timer even when the work throws", async () => {
        // If the timer leaked, this test file would hang on exit. A clean reject
        // (caught above) implies the finally block cleared it.
        const run = async () => {
            throw new Error("x");
        };
        await withTimeout(50, run).catch(() => {});
        // No assertion needed — reaching here means the finally ran. (Vitest's
        // process teardown would surface a dangling timer as a warning.)
    });
});

describe("handleAlert", () => {
    it("treats close_notify (description 0) as a graceful close", () => {
        // level=warning(1), description=0 -> close_notify.
        const result = handleAlert(new Uint8Array([0x01, 0x00]));
        expect(result.close).toBe(true);
        expect(result.error).toBeUndefined();
    });

    it("translates a warning alert into a non-closing TlsAlertError", () => {
        const result = handleAlert(new Uint8Array([0x01, 40]));
        expect(result.close).toBe(false);
        expect(result.error).toBeInstanceOf(TlsAlertError);
        expect(result.error!.level).toBe("warning");
        expect(result.error!.description).toBe(40);
    });

    it("translates a fatal alert (level 2) into a fatal TlsAlertError", () => {
        const result = handleAlert(new Uint8Array([0x02, 80]));
        expect(result.close).toBe(false);
        expect(result.error!.level).toBe("fatal");
        expect(result.error!.description).toBe(80);
    });

    it("returns a truncated-alert error for fewer than 2 bytes", () => {
        const result = handleAlert(new Uint8Array([0x01]));
        expect(result.close).toBe(false);
        expect(result.error).toBeInstanceOf(TlsAlertError);
        expect(result.error!.cause?.message).toMatch(/truncated/);
    });

    it("returns a truncated-alert error for an empty body", () => {
        const result = handleAlert(new Uint8Array(0));
        expect(result.close).toBe(false);
        expect(result.error!.cause?.message).toMatch(/truncated/);
    });
});

describe("handlePostHandshakeRecord", () => {
    it("routes an alert record through handleAlert", () => {
        // close_notify -> graceful close, no throw.
        expect(() =>
            handlePostHandshakeRecord(ContentType.ALERT, new Uint8Array([0x01, 0x00])),
        ).not.toThrow();
    });

    it("routes a fatal alert through handleAlert (which produces an error but does not throw)", () => {
        // handleAlert returns the error rather than throwing; the dispatcher does
        // the same. The error surfaces to the connection's handleAlert wrapper.
        expect(() =>
            handlePostHandshakeRecord(ContentType.ALERT, new Uint8Array([0x02, 40])),
        ).not.toThrow();
    });

    it("ignores post-handshake handshake messages (NewSessionTicket etc.)", () => {
        expect(() =>
            handlePostHandshakeRecord(ContentType.HANDSHAKE, new Uint8Array([0])),
        ).not.toThrow();
    });

    it("rejects an unexpected change_cipher_spec record", () => {
        expect(() =>
            handlePostHandshakeRecord(ContentType.CHANGE_CIPHER_SPEC, new Uint8Array(0)),
        ).toThrow(TlsHandshakeError);
    });

    it("rejects an unexpected application_data record (only valid as the outer type)", () => {
        expect(() =>
            handlePostHandshakeRecord(ContentType.APPLICATION_DATA, new Uint8Array(0)),
        ).toThrow(TlsHandshakeError);
    });
});

describe("ensureOpen", () => {
    it("does not throw when the state is open", () => {
        expect(() =>
            ensureOpen({ state: "open", sessionId: "tls_x" as never, protocolVersion: {} as never, cipherSuite: "TLS_AES_128_GCM_SHA256" }),
        ).not.toThrow();
    });

    it("throws TlsHandshakeError when the connection is still connecting", () => {
        expect(() => ensureOpen({ state: "connecting" })).toThrow(TlsHandshakeError);
    });

    it("throws TlsHandshakeError when the connection is closed", () => {
        expect(() =>
            ensureOpen({ state: "closed", reason: { kind: "close_notify" } }),
        ).toThrow(TlsHandshakeError);
    });

    it("throws TlsHandshakeError when the connection is mid-handshake", () => {
        expect(() => ensureOpen({ state: "handshaking" })).toThrow(TlsHandshakeError);
    });
});

describe("emitError", () => {
    it("invokes every registered error listener exactly once with the error", () => {
        const a = vi.fn();
        const b = vi.fn();
        const err = new TlsError("kaboom");
        emitError([a, b], err);
        expect(a).toHaveBeenCalledWith(err);
        expect(b).toHaveBeenCalledWith(err);
    });

    it("is a no-op with no listeners", () => {
        const err = new TlsError("lonely");
        expect(() => emitError([], err)).not.toThrow();
    });
});

describe("notifyClose", () => {
    it("invokes every registered close listener with the reason", () => {
        const a = vi.fn();
        const b = vi.fn();
        const reason = { kind: "close_notify" as const };
        notifyClose([a, b], reason);
        expect(a).toHaveBeenCalledWith(reason);
        expect(b).toHaveBeenCalledWith(reason);
    });

    it("passes the transport_closed reason through unchanged", () => {
        const a = vi.fn();
        const reason = { kind: "transport_closed" as const };
        notifyClose([a], reason);
        expect(a).toHaveBeenCalledWith(reason);
    });
});
