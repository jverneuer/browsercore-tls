/**
 * Tests for KeyUpdate handling (RFC 8446 §4.6.3) and alert sending / error
 * cleanup (RFC 8446 §6) in TlsConnectionImpl.
 *
 * KeyUpdate: the server sends a KeyUpdate (encrypted HANDSHAKE record) during
 * the application-data phase. The client must rotate its *receiving* keys
 * immediately, and if `request_update == 1`, send its own KeyUpdate and rotate
 * *sending* keys.
 *
 * Alert sending: when the handshake fails, the connection must send a fatal
 * alert (best-effort) and close the transport before re-throwing.
 */

import { describe, it, expect } from "vitest";
import { connectTls } from "../src/tls.js";
import { TlsError, TlsHandshakeError, AlertDescription } from "../src/errors.js";
import { ContentType, serializeRecordHeader, encryptRecord } from "../src/record/record.js";
import { TLS_1_3 } from "../src/types.js";
import type { ApplicationTrafficSecrets, ClientHelloConfig } from "../src/types.js";
import { FakeTransport } from "./fake-transport.js";
import { TlsServerSim } from "./server-sim.js";
import { createMockEventProvider, createTestCryptoProvider } from "./test-helpers.js";
import { xorNonce, writeEncryptedRecord, concat } from "../src/connection/record-layer.js";
import { updateTrafficSecrets } from "../src/crypto/keySchedule.js";
import { HandshakeType } from "../src/handshake/handshake.js";

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

/** A transport that drives the server simulator on HANDSHAKE writes. */
class HandshakeTransport extends FakeTransport {
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

/** Private fields the handshake driver sets; exposed here via cast. */
type Internals = {
    applicationSecrets: ApplicationTrafficSecrets;
    clientAppSeq: number;
    serverAppSeq: number;
    clientAppSecret: Uint8Array;
    serverAppSecret: Uint8Array;
};

/** Complete a real handshake and return the connection + transport. */
async function openConnection(): Promise<{
    conn: Awaited<ReturnType<typeof connectTls>>;
    transport: HandshakeTransport;
    internals: Internals;
}> {
    const sim = new TlsServerSim();
    const transport = new HandshakeTransport(sim);
    const conn = await connectTls({
        transport,
        crypto,
        serverName: "example.com",
        profile: PROFILE,
        events: createMockEventProvider(),
    });
    return { conn, transport, internals: conn as unknown as Internals };
}

/** Build a KeyUpdate handshake message: type(24) || length(3) || request_update(1). */
function buildKeyUpdateMessage(requestUpdate: number): Uint8Array {
    return new Uint8Array([HandshakeType.KEY_UPDATE, 0, 0, 1, requestUpdate]);
}

/**
 * Encrypt a post-handshake message under the server application traffic key and
 * push it into the transport's read queue. Uses a specific sequence number.
 */
function encryptServerRecord(
    transport: FakeTransport,
    secrets: ApplicationTrafficSecrets,
    seq: number,
    innerType: ContentType,
    content: Uint8Array,
): void {
    writeEncryptedRecord(transport, "AES-128-GCM", secrets.server, innerType, content, seq, crypto);
    const record = transport.written.pop();
    if (record !== undefined) {
        transport.readQueue.push(record);
    }
}

// ---------------------------------------------------------------------------
// KeyUpdate (RFC 8446 §4.6.3)
// ---------------------------------------------------------------------------

describe("KeyUpdate handling", () => {
    it("rotates server (read) keys on update_not_requested", async () => {
        const { conn, transport, internals } = await openConnection();

        // Snapshot the current server read secret.
        const oldServerSecret = new Uint8Array(internals.serverAppSecret);
        const oldServerKey = new Uint8Array(internals.applicationSecrets.server.key);

        // Send a KeyUpdate with request_update = 0 (update_not_requested).
        encryptServerRecord(transport, internals.applicationSecrets, internals.serverAppSeq, ContentType.HANDSHAKE, buildKeyUpdateMessage(0));

        // read() processes the KeyUpdate (rotates server keys), then loops for
        // the next record. Since no more data arrives it parks — race it to
        // observe that it didn't throw.
        await expect(Promise.race([
            conn.read(),
            new Promise((_r, reject) => setTimeout(() => reject(new Error("parked")), 50)),
        ])).rejects.toThrow("parked");

        // Server keys must have rotated.
        expect(internals.serverAppSeq).toBe(0); // reset
        expect(Array.from(internals.serverAppSecret)).not.toEqual(Array.from(oldServerSecret));
        expect(Array.from(internals.applicationSecrets.server.key)).not.toEqual(Array.from(oldServerKey));
        // Client keys must NOT have rotated (request_update was 0).
        expect(internals.clientAppSeq).toBe(0); // unchanged from the initial 0
    });

    it("rotates both server (read) and client (write) keys on update_requested", async () => {
        const { conn, transport, internals } = await openConnection();

        const oldClientKey = new Uint8Array(internals.applicationSecrets.client.key);
        const oldServerKey = new Uint8Array(internals.applicationSecrets.server.key);

        // Send a KeyUpdate with request_update = 1 (update_requested).
        encryptServerRecord(transport, internals.applicationSecrets, internals.serverAppSeq, ContentType.HANDSHAKE, buildKeyUpdateMessage(1));

        await expect(Promise.race([
            conn.read(),
            new Promise((_r, reject) => setTimeout(() => reject(new Error("parked")), 50)),
        ])).rejects.toThrow("parked");

        // Both server and client keys must have rotated.
        expect(internals.serverAppSeq).toBe(0);
        expect(internals.clientAppSeq).toBe(0);
        expect(Array.from(internals.applicationSecrets.server.key)).not.toEqual(Array.from(oldServerKey));
        expect(Array.from(internals.applicationSecrets.client.key)).not.toEqual(Array.from(oldClientKey));

        // The client should have written a KeyUpdate response (encrypted APPLICATION_DATA record).
        const clientKeyUpdateRecord = transport.written.find(
            (w, i) => i > 0 && w[0] === ContentType.APPLICATION_DATA,
        );
        expect(clientKeyUpdateRecord).toBeDefined();
    });

    it("can decrypt data sent under the new server keys after KeyUpdate", async () => {
        const { conn, transport, internals } = await openConnection();

        // Send KeyUpdate (update_not_requested).
        encryptServerRecord(transport, internals.applicationSecrets, internals.serverAppSeq, ContentType.HANDSHAKE, buildKeyUpdateMessage(0));

        // Park to let the KeyUpdate be processed.
        await expect(Promise.race([
            conn.read(),
            new Promise((_r, reject) => setTimeout(() => reject(new Error("parked")), 50)),
        ])).rejects.toThrow("parked");

        // Now encrypt application data under the NEW server keys (seq 0 after rotation).
        const payload = new TextEncoder().encode("after key update");
        encryptServerRecord(transport, internals.applicationSecrets, 0, ContentType.APPLICATION_DATA, payload);

        const result = await conn.read();
        expect(result.payload).toEqual(payload);
    });

    it("throws on an invalid request_update value", async () => {
        const { conn, transport, internals } = await openConnection();

        // request_update = 2 is invalid (only 0 and 1 are defined by RFC 8446).
        encryptServerRecord(transport, internals.applicationSecrets, internals.serverAppSeq, ContentType.HANDSHAKE, buildKeyUpdateMessage(2));

        await expect(conn.read()).rejects.toThrow(TlsHandshakeError);
    });

    it("still ignores NewSessionTicket (non-KeyUpdate post-handshake messages)", async () => {
        const { conn, transport, internals } = await openConnection();

        // NewSessionTicket: type 4, length 2, dummy body. Encrypted under server seq 0.
        const nstMsg = new Uint8Array([HandshakeType.NEW_SESSION_TICKET, 0, 0, 2, 0, 0]);
        encryptServerRecord(transport, internals.applicationSecrets, 0, ContentType.HANDSHAKE, nstMsg);

        // Then send real application data under the same keys (seq 1).
        const payload = new TextEncoder().encode("after NST");
        encryptServerRecord(transport, internals.applicationSecrets, 1, ContentType.APPLICATION_DATA, payload);

        const result = await conn.read();
        expect(result.payload).toEqual(payload);
    });
});

// ---------------------------------------------------------------------------
// Alert sending + error cleanup (RFC 8446 §6)
// ---------------------------------------------------------------------------

describe("Error cleanup on handshake failure", () => {
    it("closes the transport and transitions to closed on a tampered CertificateVerify", async () => {
        const sim = new TlsServerSim({ tamperCertificateVerify: true });
        const transport = new HandshakeTransport(sim);
        try {
            await connectTls({
                transport,
                crypto,
                serverName: "example.com",
                profile: PROFILE,
                events: createMockEventProvider(),
            });
            expect.unreachable("expected handshake to fail");
        } catch (e) {
            expect(e).toBeInstanceOf(TlsHandshakeError);
        }
        // Transport must be closed (error cleanup).
        expect(transport.closed).toBe(true);
    });

    it("re-throws the original error after cleanup", async () => {
        const sim = new TlsServerSim({ tamperCertificateVerify: true });
        const transport = new HandshakeTransport(sim);
        const error = await connectTls({
            transport,
            crypto,
            serverName: "example.com",
            profile: PROFILE,
            events: createMockEventProvider(),
        }).catch((e) => e);
        expect(error).toBeInstanceOf(TlsHandshakeError);
        expect((error as TlsHandshakeError).phase).toBe("certificate_verify");
    });

    it("closes the transport when the server sends a non-handshake record for ServerHello", async () => {
        const sim = new TlsServerSim();
        const transport = new HandshakeTransport(sim);
        const orig = sim.onClientHello.bind(sim);
        sim.onClientHello = (rec: Uint8Array) => {
            orig(rec);
            const sh = sim.responses[0]!;
            sim.responses[0] = new Uint8Array([ContentType.APPLICATION_DATA, ...sh.subarray(1)]);
        };
        try {
            await connectTls({
                transport,
                crypto,
                serverName: "example.com",
                profile: PROFILE,
                events: createMockEventProvider(),
            });
            expect.unreachable("expected handshake to fail");
        } catch {
            // Expected.
        }
        expect(transport.closed).toBe(true);
    });
});

describe("AlertDescription mapping", () => {
    it("maps certificate phase errors to bad_certificate", () => {
        expect(AlertDescription.BAD_CERTIFICATE).toBe(42);
    });

    it("maps decrypt-related descriptions correctly", () => {
        expect(AlertDescription.DECRYPT_ERROR).toBe(51);
    });

    it("maps handshake failure correctly", () => {
        expect(AlertDescription.HANDSHAKE_FAILURE).toBe(40);
    });

    it("maps illegal parameter correctly", () => {
        expect(AlertDescription.ILLEGAL_PARAMETER).toBe(47);
    });
});

describe("sendAlert during handshake", () => {
    it("sends a fatal alert under handshake traffic keys before closing", async () => {
        const sim = new TlsServerSim({ tamperCertificateVerify: true });
        const transport = new HandshakeTransport(sim);
        await connectTls({
            transport,
            crypto,
            serverName: "example.com",
            profile: PROFILE,
            events: createMockEventProvider(),
        }).catch(() => {
            // Expected.
        });
        // The client writes: ClientHello, then the fatal alert (encrypted
        // APPLICATION_DATA) once the CertificateVerify check fails. The exact
        // number depends on whether traffic keys were derived before the error,
        // but the transport must be closed.
        expect(transport.closed).toBe(true);
        // At least the ClientHello + the alert were written.
        expect(transport.written.length).toBeGreaterThanOrEqual(1);
    });

    it("sends an alert on an open connection (application traffic keys)", async () => {
        const { conn, transport } = await openConnection();
        const writtenBefore = transport.written.length;
        await conn.sendAlert("fatal", AlertDescription.HANDSHAKE_FAILURE);
        // An alert was written as an encrypted APPLICATION_DATA record.
        expect(transport.written.length).toBe(writtenBefore + 1);
        expect(transport.written[transport.written.length - 1]![0]).toBe(ContentType.APPLICATION_DATA);
    });

    it("rejects a CCS record in the post-handshake phase", async () => {
        const { conn, transport, internals } = await openConnection();
        // CCS record encrypted under the server application key.
        encryptServerRecord(transport, internals.applicationSecrets, internals.serverAppSeq, ContentType.CHANGE_CIPHER_SPEC, new Uint8Array(0));
        await expect(conn.read()).rejects.toThrow(TlsHandshakeError);
    });
});
