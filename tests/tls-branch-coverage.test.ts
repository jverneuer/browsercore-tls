/**
 * Branch coverage tests for src/tls.ts.
 *
 * Covers the remaining uncovered branches, functions, and statements in
 * TlsConnectionImpl and generateKeyShares that the connection-level tests
 * (tls-connection.test.ts) and the alert-mapping coverage tests
 * (alert-mapping-coverage.test.ts) do not exercise.
 *
 * Branches covered:
 * - generateKeyShares: PQ hybrid group cases (X25519Kyber768, X25519MLKEM768,
 *   Secp256r1MLKEM768, Secp384r1MLKEM1024)
 * - TlsConnectionImpl constructor: missing EventProvider guard
 * - EventProvider delegation: once, off, removeListener, emit,
 *   listenerCount, removeAllListeners
 * - errorToAlertDescription: INTERNAL_ERROR for non-TLS cause
 * - errorToAlertDescription: nullish coalescing fallback when cause.cause is
 *   undefined
 * - sendAlert: non-fatal (warning) alert level ternary
 */

import { describe, it, expect, vi } from "vitest";
import { TlsConnectionImpl, generateKeyShares } from "../src/tls.js";
import {
    TlsError,
    TlsHandshakeError,
    AlertDescription,
    type TlsError as TlsErrorType,
} from "../src/errors.js";
import { createTestCryptoProvider, createMockEventProvider } from "./test-helpers.js";
import { FakeTransport } from "./fake-transport.js";
import { ContentType } from "../src/record/record.js";
import {
    TLS_1_3,
    type ApplicationTrafficSecrets,
    type TlsState,
    type ClientHelloConfig,
    type TlsOptions,
} from "../src/types.js";

const crypto = createTestCryptoProvider();

const BASE_PROFILE: ClientHelloConfig = {
    cipherSuites: ["TLS_AES_128_GCM_SHA256"],
    extensionOrder: [
        0, 10, 11, 13, 16, 17613, 18, 23, 27, 35, 41, 43, 45, 5, 51, 65281,
    ],
    keyShareGroups: ["x25519"],
    signatureAlgorithms: ["ecdsa_secp256r1_sha256"],
    supportedVersions: [TLS_1_3],
    serverName: "example.com",
    grease: true,
};

/** Private fields the handshake driver would set; exposed here via cast. */
type Internals = {
    applicationSecrets: ApplicationTrafficSecrets;
    clientAppSeq: number;
    serverAppSeq: number;
    appReadQueue: Uint8Array[];
    transition(next: TlsState): void;
};

const KEY16 = new Uint8Array(16).fill(0x01);
const IV12 = new Uint8Array(12).fill(0x02);
const SECRETS: ApplicationTrafficSecrets = {
    client: { key: KEY16, iv: IV12 },
    server: { key: new Uint8Array(16).fill(0x03), iv: new Uint8Array(12).fill(0x04) },
};

/** Build a connection whose internals are set up as if the handshake completed. */
function openConnection(): TlsConnectionImpl {
    const transport = new FakeTransport();
    const conn = new TlsConnectionImpl({
        transport,
        serverName: "example.com",
        profile: BASE_PROFILE,
        crypto,
        events: createMockEventProvider(),
    }, crypto);
    const internals = conn as unknown as Internals;
    internals.applicationSecrets = SECRETS;
    conn.aead = "AES-128-GCM";
    internals.transition({
        state: "open",
        sessionId: conn.id,
        protocolVersion: TLS_1_3,
        cipherSuite: "TLS_AES_128_GCM_SHA256",
    });
    return conn;
}

/**
 * Access the private errorToAlertDescription method on a TlsConnectionImpl.
 * Constructed without options — the method is pure and touches no state.
 */
function errorToAlertDescription(error: TlsErrorType): number {
    const conn = new TlsConnectionImpl(undefined, crypto);
    return (
        conn as unknown as { errorToAlertDescription(e: TlsErrorType): number }
    ).errorToAlertDescription.call(conn, error);
}

// -------------------------------------------------------------------------
// generateKeyShares — PQ hybrid group cases
// -------------------------------------------------------------------------

describe("generateKeyShares — PQ hybrid groups", () => {
    it("generates an X25519 key tagged as X25519Kyber768", async () => {
        const shares = await generateKeyShares(["X25519Kyber768"], crypto);
        expect(shares).toHaveLength(1);
        expect(shares[0]!.algorithm).toBe("X25519Kyber768");
        // X25519 public keys are always 32 bytes (RFC 7748).
        expect(shares[0]!.publicKey.length).toBe(32);
        expect(shares[0]!.privateKey.length).toBe(32);
    });

    it("generates an X25519 key tagged as X25519MLKEM768", async () => {
        const shares = await generateKeyShares(["X25519MLKEM768"], crypto);
        expect(shares).toHaveLength(1);
        expect(shares[0]!.algorithm).toBe("X25519MLKEM768");
        expect(shares[0]!.publicKey.length).toBe(32);
    });

    it("generates an X25519 key for Secp256r1MLKEM768", async () => {
        const shares = await generateKeyShares(["Secp256r1MLKEM768"], crypto);
        expect(shares).toHaveLength(1);
        // The PQ hybrid falls through to the X25519 backend, tagged as "x25519".
        expect(shares[0]!.algorithm).toBe("x25519");
        expect(shares[0]!.publicKey.length).toBe(32);
    });

    it("generates an X25519 key for Secp384r1MLKEM1024", async () => {
        const shares = await generateKeyShares(["Secp384r1MLKEM1024"], crypto);
        expect(shares).toHaveLength(1);
        expect(shares[0]!.algorithm).toBe("x25519");
    });
});

// -------------------------------------------------------------------------
// TlsConnectionImpl constructor — missing EventProvider guard
// -------------------------------------------------------------------------

describe("TlsConnectionImpl constructor — missing EventProvider", () => {
    it("throws TlsHandshakeError when options.events is undefined", () => {
        // Intentionally omit `events` to exercise the composition-root guard.
        // The cast is safe: the constructor checks at runtime, not compile time.
        const optsWithoutEvents = {
            transport: new FakeTransport(),
            serverName: "example.com",
            profile: BASE_PROFILE,
            crypto,
        } as Omit<TlsOptions, "events"> as TlsOptions;

        expect(() => new TlsConnectionImpl(optsWithoutEvents, crypto)).toThrow(TlsHandshakeError);

        try {
            new TlsConnectionImpl(optsWithoutEvents, crypto);
            expect.unreachable("expected constructor to throw");
        } catch (e) {
            const err = e as TlsHandshakeError;
            expect(err.phase).toBe("client_hello");
            expect(err.cause?.message).toMatch(/requires an injected EventProvider/);
        }
    });
});

// -------------------------------------------------------------------------
// EventProvider delegation — once, off, removeListener, emit,
// listenerCount, removeAllListeners
// -------------------------------------------------------------------------

describe("EventProvider delegation methods", () => {
    function makeConn(): TlsConnectionImpl {
        return new TlsConnectionImpl({
            transport: new FakeTransport(),
            serverName: "example.com",
            profile: BASE_PROFILE,
            crypto,
            events: createMockEventProvider(),
        }, crypto);
    }

    it("once() registers a listener that fires exactly once then auto-removes", () => {
        const conn = makeConn();
        const listener = vi.fn();
        conn.once("test", listener);
        expect(conn.listenerCount("test")).toBe(1);

        conn.emit("test", "first");
        expect(listener).toHaveBeenCalledWith("first");

        // once() auto-removes after the first invocation.
        expect(conn.listenerCount("test")).toBe(0);
        conn.emit("test", "second");
        expect(listener).toHaveBeenCalledTimes(1);
    });

    it("off() removes a previously registered listener", () => {
        const conn = makeConn();
        const listener = vi.fn();
        conn.on("close", listener);
        expect(conn.listenerCount("close")).toBe(1);

        conn.off("close", listener);
        expect(conn.listenerCount("close")).toBe(0);
    });

    it("removeListener() removes a previously registered listener", () => {
        const conn = makeConn();
        const listener = vi.fn();
        conn.on("error", listener);
        expect(conn.listenerCount("error")).toBe(1);

        conn.removeListener("error", listener);
        expect(conn.listenerCount("error")).toBe(0);
    });

    it("emit() returns true when a listener exists, false otherwise", () => {
        const conn = makeConn();
        expect(conn.emit("nothing", "x")).toBe(false);

        conn.on("close", () => {});
        expect(conn.emit("close", { kind: "close_notify" })).toBe(true);
    });

    it("listenerCount() returns the number of registered listeners for an event", () => {
        const conn = makeConn();
        expect(conn.listenerCount("close")).toBe(0);

        conn.on("close", () => {});
        conn.on("close", () => {});
        expect(conn.listenerCount("close")).toBe(2);
    });

    it("removeAllListeners() with no argument clears all events", () => {
        const conn = makeConn();
        conn.on("close", () => {});
        conn.on("error", () => {});

        conn.removeAllListeners();
        expect(conn.listenerCount("close")).toBe(0);
        expect(conn.listenerCount("error")).toBe(0);
    });

    it("removeAllListeners(event) clears one event only", () => {
        const conn = makeConn();
        conn.on("close", () => {});
        conn.on("error", () => {});

        conn.removeAllListeners("close");
        expect(conn.listenerCount("close")).toBe(0);
        expect(conn.listenerCount("error")).toBe(1);
    });
});

// -------------------------------------------------------------------------
// errorToAlertDescription — remaining paths
// -------------------------------------------------------------------------

describe("errorToAlertDescription — INTERNAL_ERROR and nullish fallback", () => {
    it("maps a plain Error cause to INTERNAL_ERROR (80)", () => {
        // The cause is not a TlsHandshakeError or TlsDecryptError — falls
        // through every instanceof check to the final INTERNAL_ERROR return.
        const error = new TlsError("unexpected failure", {}, {
            cause: new Error("something went wrong"),
        });
        expect(errorToAlertDescription(error)).toBe(AlertDescription.INTERNAL_ERROR);
    });

    it("maps a null cause to INTERNAL_ERROR (80)", () => {
        // ensureTlsError can produce a TlsError with no cause at all.
        const error = new TlsError("no cause error");
        expect(errorToAlertDescription(error)).toBe(AlertDescription.INTERNAL_ERROR);
    });

    it("falls back to empty string when cause.cause is undefined", () => {
        // A TlsHandshakeError with no inner cause → cause.cause?.message is
        // undefined → the ?? "" fallback kicks in. The empty message does not
        // contain "downgrade" or "illegal", and the phase is "server_hello"
        // (not certificate/verify/finished) → HANDSHAKE_FAILURE.
        const error = new TlsError("handshake error", {}, {
            cause: new TlsHandshakeError("server_hello"),
        });
        expect(errorToAlertDescription(error)).toBe(AlertDescription.HANDSHAKE_FAILURE);
    });
});

// -------------------------------------------------------------------------
// sendAlert — non-fatal (warning) alert level ternary
// -------------------------------------------------------------------------

describe("sendAlert — warning level", () => {
    it("sends a warning alert (level 0x01) on an open connection", async () => {
        const conn = openConnection();
        const transport = (conn as unknown as { transport: FakeTransport }).transport;

        await conn.sendAlert("warning", AlertDescription.CLOSE_NOTIFY);

        // The alert was encrypted and written as an APPLICATION_DATA record.
        expect(transport.written.length).toBe(1);
        expect(transport.written[0]![0]).toBe(ContentType.APPLICATION_DATA);
        // clientAppSeq incremented from 0 to 1.
        expect((conn as unknown as Internals).clientAppSeq).toBe(1);
    });
});
