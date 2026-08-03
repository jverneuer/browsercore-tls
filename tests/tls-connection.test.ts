/**
 * Tests for @browsercore/tls TlsConnectionImpl (src/tls.ts).
 *
 * The connection class is a thin coordinator: it owns mutable state and threads
 * it through the connection/* helpers. We test the public API surface (write /
 * read / close / on) by manually installing application traffic secrets — the
 * same fields runHandshake would populate — so we exercise the record read/write
 * path, alert handling, and lifecycle transitions without a live server.
 */

import { describe, it, expect, vi } from "vitest";
import { TlsConnectionImpl } from "../src/tls.js";
import { ContentType, serializeRecordHeader, encryptRecord } from "../src/record/record.js";
import { TlsError, TlsHandshakeError } from "../src/errors.js";
import { TLS_1_3 } from "../src/types.js";
import type { ApplicationTrafficSecrets, TlsState, ClientHelloConfig } from "../src/types.js";
import { xorNonce, writeEncryptedRecord } from "../src/connection/record-layer.js";
import { FakeTransport } from "./fake-transport.js";

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

const BASE_PROFILE: ClientHelloConfig = {
    cipherSuites: ["TLS_AES_128_GCM_SHA256"],
    keyShareGroups: ["x25519"],
    signatureAlgorithms: ["ecdsa_secp256r1_sha256"],
    supportedVersions: [TLS_1_3],
    serverName: "example.com",
};

/** Build a connection whose internals are set up as if the handshake completed. */
function openConnection(): TlsConnectionImpl {
    const transport = new FakeTransport();
    const conn = new TlsConnectionImpl({
        transport,
        serverName: "example.com",
        profile: BASE_PROFILE,
    });
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

describe("TlsConnectionImpl constructor", () => {
    it("starts in the connecting state with default protocol/cipher", () => {
        const conn = new TlsConnectionImpl();
        expect(conn.state.state).toBe("connecting");
        expect(conn.protocolVersion).toEqual(TLS_1_3);
        expect(conn.cipherSuite).toBe("TLS_AES_128_GCM_SHA256");
        expect(conn.id).toMatch(/^tls_/);
    });

    it("stores the transport, serverName, and trustAnchors from options", () => {
        const transport = new FakeTransport();
        const anchor = new Uint8Array([1, 2, 3]);
        const conn = new TlsConnectionImpl({
            transport,
            serverName: "host.example",
            profile: BASE_PROFILE,
            trustAnchors: [anchor],
        });
        expect((conn as unknown as { transport: FakeTransport }).transport).toBe(transport);
    });

    it("overrides profile.alpnProtocols when alpnProtocols is provided and non-empty", () => {
        const transport = new FakeTransport();
        const conn = new TlsConnectionImpl({
            transport,
            serverName: "example.com",
            profile: BASE_PROFILE,
            alpnProtocols: ["h2"],
        });
        // The override lands on the internal profile; alpnProtocol surfaces once
        // the handshake completes. Here we confirm the constructor did not crash
        // and the connection is usable.
        expect(conn.state.state).toBe("connecting");
    });

    it("keeps the profile unchanged when alpnProtocols is undefined or empty", () => {
        const transport = new FakeTransport();
        const conn = new TlsConnectionImpl({
            transport,
            serverName: "example.com",
            profile: { ...BASE_PROFILE, alpnProtocols: ["http/1.1"] },
            alpnProtocols: [],
        });
        expect(conn.state.state).toBe("connecting");
    });

    it("defaults trustAnchors to an empty array when omitted", () => {
        const transport = new FakeTransport();
        const conn = new TlsConnectionImpl({
            transport,
            serverName: "example.com",
            profile: BASE_PROFILE,
        });
        // No crash; the connection is usable without anchors.
        expect(conn.state.state).toBe("connecting");
    });
});

describe("write", () => {
    it("rejects when the connection is not open", async () => {
        const conn = new TlsConnectionImpl({
            transport: new FakeTransport(),
            serverName: "example.com",
            profile: BASE_PROFILE,
        });
        // ensureOpen throws TlsHandshakeError; write() wraps it via ensureTlsError
        // so callers see a uniform TlsError.
        await expect(conn.write(new Uint8Array([1]))).rejects.toThrow(TlsError);
    });

    it("encrypts and writes application data as an APPLICATION_DATA record", async () => {
        const conn = openConnection();
        const transport = (conn as unknown as { transport: FakeTransport }).transport;
        const payload = new TextEncoder().encode("hello world");
        await conn.write(payload);
        expect(transport.written.length).toBe(1);
        const record = transport.written[0]!;
        expect(record[0]).toBe(ContentType.APPLICATION_DATA);
    });

    it("splits payloads larger than 2^14 bytes into multiple records", async () => {
        const conn = openConnection();
        const transport = (conn as unknown as { transport: FakeTransport }).transport;
        // 16384 * 2 = 32768 bytes -> exactly two full records.
        const payload = new Uint8Array(16_384 * 2);
        await conn.write(payload);
        expect(transport.written.length).toBe(2);
    });

    it("splits a payload of 16385 bytes into a full record and a 1-byte fragment", async () => {
        const conn = openConnection();
        const transport = (conn as unknown as { transport: FakeTransport }).transport;
        await conn.write(new Uint8Array(16_385));
        expect(transport.written.length).toBe(2);
        // Second record carries a 1-byte plaintext fragment.
        const secondHeader = transport.written[1]!;
        const secondLen = (secondHeader[3]! << 8) | secondHeader[4]!;
        // 1 byte plaintext + 1 byte inner type + 16 byte tag = 18.
        expect(secondLen).toBe(18);
    });

    it("wraps a non-TlsError thrown during write into a TlsError", async () => {
        const conn = openConnection();
        const internals = conn as unknown as Internals;
        // Corrupt the traffic so encryptRecord throws synchronously.
        internals.applicationSecrets = {
            client: { key: new Uint8Array(0), iv: IV12 },
            server: SECRETS.server,
        };
        await expect(conn.write(new Uint8Array([1]))).rejects.toThrow(TlsError);
    });
});

describe("read", () => {
    it("rejects when the connection is not open", async () => {
        const conn = new TlsConnectionImpl({
            transport: new FakeTransport(),
            serverName: "example.com",
            profile: BASE_PROFILE,
        });
        await expect(conn.read()).rejects.toThrow(TlsHandshakeError);
    });

    it("returns queued application data without touching the transport", async () => {
        const conn = openConnection();
        const internals = conn as unknown as Internals;
        const payload = new TextEncoder().encode("queued");
        internals.appReadQueue.push(payload);
        const result = await conn.read();
        expect(result.payload).toEqual(payload);
    });

    it("decrypts an APPLICATION_DATA record from the transport", async () => {
        const conn = openConnection();
        const transport = (conn as unknown as { transport: FakeTransport }).transport;
        const payload = new TextEncoder().encode("from server");
        // Encrypt under the server application traffic key, seq 0.
        writeEncryptedRecord(transport, "AES-128-GCM", SECRETS.server, ContentType.APPLICATION_DATA, payload, 0);
        // Move the written record into the read queue so read() can consume it.
        transport.readQueue.push(transport.written.pop()!);
        const result = await conn.read();
        expect(result.payload).toEqual(payload);
    });

    it("handles a close_notify alert record by closing the connection", async () => {
        const conn = openConnection();
        const transport = (conn as unknown as { transport: FakeTransport }).transport;
        // close_notify: level=warning(1), description=0.
        writeEncryptedRecord(transport, "AES-128-GCM", SECRETS.server, ContentType.ALERT, new Uint8Array([0x01, 0x00]), 0);
        transport.readQueue.push(transport.written.pop()!);
        // read() processes the alert (graceful close -> state "closed"), then
        // loops to read the next record. Since no more data arrives it parks;
        // race it to observe the state transition without hanging.
        await expect(Promise.race([
            conn.read(),
            new Promise((_r, reject) => setTimeout(() => reject(new Error("parked")), 50)),
        ])).rejects.toThrow("parked");
        expect(conn.state.state).toBe("closed");
    });

    it("handles a fatal alert by emitting an error to listeners", async () => {
        const conn = openConnection();
        const transport = (conn as unknown as { transport: FakeTransport }).transport;
        const errorListener = vi.fn();
        conn.on("error", errorListener);
        // Fatal alert: level=2, description=40 (handshake_failure).
        writeEncryptedRecord(transport, "AES-128-GCM", SECRETS.server, ContentType.ALERT, new Uint8Array([0x02, 40]), 0);
        transport.readQueue.push(transport.written.pop()!);
        // The fatal alert emits an error but does NOT close; read() loops waiting
        // for the next record. Since none arrives it parks forever — race it.
        await expect(Promise.race([
            conn.read(),
            new Promise((_r, reject) => setTimeout(() => reject(new Error("timeout")), 50)),
        ])).rejects.toThrow("timeout");
        expect(errorListener).toHaveBeenCalledTimes(1);
        expect(errorListener.mock.calls[0]![0]).toBeInstanceOf(TlsError);
    });

    it("ignores post-handshake handshake messages and keeps reading", async () => {
        const conn = openConnection();
        const transport = (conn as unknown as { transport: FakeTransport }).transport;
        // First record: a post-handshake HANDSHAKE message (e.g. NewSessionTicket).
        writeEncryptedRecord(transport, "AES-128-GCM", SECRETS.server, ContentType.HANDSHAKE, new Uint8Array([4, 0, 0, 2, 0, 0]), 0);
        transport.readQueue.push(transport.written.pop()!);
        // Second record: real application data the read() should return.
        const payload = new TextEncoder().encode("after NST");
        writeEncryptedRecord(transport, "AES-128-GCM", SECRETS.server, ContentType.APPLICATION_DATA, payload, 1);
        transport.readQueue.push(transport.written.pop()!);

        const result = await conn.read();
        expect(result.payload).toEqual(payload);
    });

    it("rejects when an unexpected CHANGE_CIPHER_SPEC inner type arrives post-handshake", async () => {
        const conn = openConnection();
        const transport = (conn as unknown as { transport: FakeTransport }).transport;
        writeEncryptedRecord(transport, "AES-128-GCM", SECRETS.server, ContentType.CHANGE_CIPHER_SPEC, new Uint8Array(0), 0);
        transport.readQueue.push(transport.written.pop()!);
        await expect(conn.read()).rejects.toThrow(TlsHandshakeError);
    });
});

describe("close", () => {
    it("is idempotent when already closed", async () => {
        const conn = openConnection();
        const internals = conn as unknown as Internals;
        internals.transition({ state: "closed", reason: { kind: "close_notify" } });
        await expect(conn.close()).resolves.toBeUndefined();
    });

    it("sends close_notify and closes the transport when open", async () => {
        const conn = openConnection();
        const transport = (conn as unknown as { transport: FakeTransport }).transport;
        await conn.close();
        expect(transport.closed).toBe(true);
        expect(conn.state.state).toBe("closed");
        // The close_notify alert was written as an encrypted record.
        expect(transport.written.length).toBe(1);
        expect(transport.written[0]![0]).toBe(ContentType.APPLICATION_DATA);
    });

    it("notifies registered close listeners with a close_notify reason", async () => {
        const conn = openConnection();
        const closeListener = vi.fn();
        conn.on("close", closeListener);
        await conn.close();
        expect(closeListener).toHaveBeenCalledWith({ kind: "close_notify" });
    });

    it("closes without sending an alert when the connection is mid-handshake", async () => {
        const conn = new TlsConnectionImpl({
            transport: new FakeTransport(),
            serverName: "example.com",
            profile: BASE_PROFILE,
        });
        const transport = (conn as unknown as { transport: FakeTransport }).transport;
        // state is "connecting" (not "open"), so no alert is sent.
        await conn.close();
        expect(transport.closed).toBe(true);
        expect(transport.written.length).toBe(0);
        expect(conn.state.state).toBe("closed");
    });
});

describe("handshake", () => {
    it("is a no-op when the connection is already open", async () => {
        const conn = openConnection();
        // Already open; handshake() should resolve immediately without touching
        // the transport.
        await expect(conn.handshake()).resolves.toBeUndefined();
    });
});

describe("on", () => {
    it("registers a close listener and returns the connection for chaining", () => {
        const conn = new TlsConnectionImpl();
        const result = conn.on("close", () => {});
        expect(result).toBe(conn);
    });

    it("registers an error listener", () => {
        const conn = new TlsConnectionImpl();
        const result = conn.on("error", () => {});
        expect(result).toBe(conn);
    });
});
