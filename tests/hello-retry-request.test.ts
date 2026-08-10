/**
 * Tests for HelloRetryRequest handling (RFC 8446 §4.1.3, §4.2.2, §4.4.1).
 *
 * Unit tests for the HRR detection predicate, extension parsing, and synthetic
 * message_hash transcript message — plus integration tests that drive the full
 * handshake through the server simulator with HRR enabled.
 */

import { describe, it, expect } from "vitest";
import { NobleX25519Backend } from "@browsercore/crypto";
import { connectTls } from "../src/tls.js";
import { TlsHandshakeError } from "../src/errors.js";
import { ContentType } from "../src/record/record.js";
import { TLS_1_3 } from "../src/types.js";
import type { ClientHelloConfig } from "../src/types.js";
import {
    HELLO_RETRY_REQUEST_RANDOM,
    isHelloRetryRequest,
    parseHelloRetryRequestExtensions,
    buildMessageHashMessage,
} from "../src/handshake/hello-retry-request.js";
import { FakeTransport } from "./fake-transport.js";
import { TlsServerSim } from "./server-sim.js";
import { createMockEventProvider, createTestCryptoProvider } from "./test-helpers.js";

const crypto = createTestCryptoProvider();

const PROFILE: ClientHelloConfig = {
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

/** A transport that drives the sim on every HANDSHAKE write (supports HRR's two ClientHellos). */
class HrrHandshakeTransport extends FakeTransport {
    private sim: TlsServerSim;

    constructor(sim: TlsServerSim) {
        super();
        this.sim = sim;
    }

    public override async write(data: Uint8Array): Promise<void> {
        await super.write(data);
        if (data.length > 0 && data[0] === ContentType.HANDSHAKE) {
            this.sim.onClientHello(data);
            for (const resp of this.sim.responses) {
                this.readQueue.push(resp);
            }
        }
    }
}

describe("isHelloRetryRequest", () => {
    it("returns true for the sentinel random value", () => {
        expect(isHelloRetryRequest(HELLO_RETRY_REQUEST_RANDOM)).toBe(true);
    });

    it("returns false for a normal ServerHello random", () => {
        const normal = new Uint8Array(32).fill(0x55);
        expect(isHelloRetryRequest(normal)).toBe(false);
    });

    it("returns false for a random value that differs by one byte", () => {
        const near = new Uint8Array(HELLO_RETRY_REQUEST_RANDOM);
        near[0] ^= 0x01;
        expect(isHelloRetryRequest(near)).toBe(false);
    });
});

describe("buildMessageHashMessage", () => {
    it("builds a 4 + hashLen message with type 254 (message_hash)", () => {
        const hashValue = crypto.randomBytes(32);
        const msg = buildMessageHashMessage(hashValue);
        expect(msg.length).toBe(4 + 32);
        expect(msg[0]).toBe(254); // HandshakeType.MESSAGE_HASH
        // 24-bit length in bytes 1..3.
        const len = (msg[1]! << 16) | (msg[2]! << 8) | msg[3]!;
        expect(len).toBe(32);
        // Body is the hash value.
        expect(Array.from(msg.subarray(4))).toEqual(Array.from(hashValue));
    });

    it("works with a 48-byte hash (SHA-384)", () => {
        const hashValue = crypto.randomBytes(48);
        const msg = buildMessageHashMessage(hashValue);
        expect(msg.length).toBe(4 + 48);
        const len = (msg[1]! << 16) | (msg[2]! << 8) | msg[3]!;
        expect(len).toBe(48);
    });
});

describe("parseHelloRetryRequestExtensions", () => {
    /** Build a raw extensions block (length-prefixed) for testing. */
    function buildExtensionsBlock(...exts: { type: number; data: Uint8Array }[]): Uint8Array {
        const parts: Uint8Array[] = [];
        let totalDataLen = 0;
        for (const ext of exts) {
            const entry = new Uint8Array(4 + ext.data.length);
            entry[0] = (ext.type >> 8) & 0xff;
            entry[1] = ext.type & 0xff;
            entry[2] = (ext.data.length >> 8) & 0xff;
            entry[3] = ext.data.length & 0xff;
            entry.set(ext.data, 4);
            parts.push(entry);
            totalDataLen += entry.length;
        }
        const block = new Uint8Array(2 + totalDataLen);
        block[0] = (totalDataLen >> 8) & 0xff;
        block[1] = totalDataLen & 0xff;
        let o = 2;
        for (const part of parts) {
            block.set(part, o);
            o += part.length;
        }
        return block;
    }

    it("parses the selected_group from the key_share extension", () => {
        // supported_versions (0x0304) + key_share (x25519 = 0x001d).
        const block = buildExtensionsBlock(
            { type: 43, data: new Uint8Array([0x03, 0x04]) }, // supported_versions
            { type: 51, data: new Uint8Array([0x00, 0x1d]) }, // key_share: x25519
        );
        const hrr = parseHelloRetryRequestExtensions(block);
        expect(hrr.selectedGroup).toBe("x25519");
        expect(hrr.cookie).toBeUndefined();
    });

    it("parses a cookie extension when present", () => {
        const cookieBytes = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
        const cookieBody = new Uint8Array(2 + cookieBytes.length);
        cookieBody[0] = 0; cookieBody[1] = cookieBytes.length;
        cookieBody.set(cookieBytes, 2);

        const block = buildExtensionsBlock(
            { type: 43, data: new Uint8Array([0x03, 0x04]) },
            { type: 51, data: new Uint8Array([0x00, 0x1d]) },
            { type: 44, data: cookieBody }, // cookie
        );
        const hrr = parseHelloRetryRequestExtensions(block);
        expect(hrr.selectedGroup).toBe("x25519");
        expect(hrr.cookie).toEqual(cookieBytes);
    });

    it("throws when key_share extension is missing", () => {
        const block = buildExtensionsBlock(
            { type: 43, data: new Uint8Array([0x03, 0x04]) },
        );
        expect(() => parseHelloRetryRequestExtensions(block)).toThrow(TlsHandshakeError);
    });

    it("throws when key_share data is not exactly 2 bytes", () => {
        const block = buildExtensionsBlock(
            { type: 43, data: new Uint8Array([0x03, 0x04]) },
            { type: 51, data: new Uint8Array([0x00, 0x1d, 0x00]) }, // 3 bytes
        );
        expect(() => parseHelloRetryRequestExtensions(block)).toThrow(/must be exactly 2 bytes/);
    });

    it("throws when the cookie length prefix does not match the body", () => {
        // cookie_length says 10 but only 4 bytes follow.
        const cookieBody = new Uint8Array([0x00, 0x0a, 0xde, 0xad, 0xbe, 0xef]);
        const block = buildExtensionsBlock(
            { type: 43, data: new Uint8Array([0x03, 0x04]) },
            { type: 51, data: new Uint8Array([0x00, 0x1d]) },
            { type: 44, data: cookieBody },
        );
        expect(() => parseHelloRetryRequestExtensions(block)).toThrow(/cookie length does not match/);
    });

    it("throws when the cookie extension body is too short", () => {
        const block = buildExtensionsBlock(
            { type: 43, data: new Uint8Array([0x03, 0x04]) },
            { type: 51, data: new Uint8Array([0x00, 0x1d]) },
            { type: 44, data: new Uint8Array([0x00]) }, // only 1 byte — too short for length prefix
        );
        expect(() => parseHelloRetryRequestExtensions(block)).toThrow(/too short for length prefix/);
    });
});

// ---------------------------------------------------------------------------
// Integration tests: full handshake with HelloRetryRequest via TlsServerSim.
// ---------------------------------------------------------------------------

describe("connectTls with HelloRetryRequest", () => {
    it("completes the handshake when the server sends an HRR requesting x25519", async () => {
        const sim = new TlsServerSim({ helloRetryRequest: { selectedGroup: "x25519" } });
        const transport = new HrrHandshakeTransport(sim);
        const conn = await connectTls({
            transport,
            crypto,
            serverName: "example.com",
            profile: PROFILE,
            events: createMockEventProvider(),
        });
        expect(conn.state.state).toBe("open");
        expect(conn.cipherSuite).toBe("TLS_AES_128_GCM_SHA256");
        expect(conn.peerCertificate).toBeDefined();
        // Three writes: ClientHello_1, ClientHello_2, client Finished.
        const handshakeWrites = transport.written.filter((w) => w[0] === ContentType.HANDSHAKE);
        expect(handshakeWrites.length).toBe(2);
    });

    it("completes an HRR handshake with a cookie", async () => {
        const sim = new TlsServerSim({
            helloRetryRequest: {
                selectedGroup: "x25519",
                cookie: new Uint8Array([0xaa, 0xbb, 0xcc]),
            },
        });
        const transport = new HrrHandshakeTransport(sim);
        const conn = await connectTls({
            transport,
            crypto,
            serverName: "example.com",
            profile: PROFILE,
            events: createMockEventProvider(),
        });
        expect(conn.state.state).toBe("open");
    });

    it("completes an HRR handshake with an injected X25519 backend", async () => {
        const sim = new TlsServerSim({
            helloRetryRequest: { selectedGroup: "x25519" },
            x25519Backend: new NobleX25519Backend(),
        });
        const transport = new HrrHandshakeTransport(sim);
        const conn = await connectTls({
            transport,
            crypto,
            serverName: "example.com",
            profile: PROFILE,
            events: createMockEventProvider(),
        });
        expect(conn.state.state).toBe("open");
    });
});
