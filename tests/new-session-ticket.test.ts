/**
 * Tests for NewSessionTicket processing (RFC 8446 §4.6.1) through the
 * TlsConnectionImpl. Verifies that a post-handshake NewSessionTicket is
 * parsed, the resumption PSK is derived, and the result is stored in the
 * connection's session cache.
 */

import { describe, it, expect } from "vitest";
import { connectTls } from "../src/tls.js";
import { ContentType } from "../src/record/record.js";
import { HandshakeType } from "../src/handshake/handshake.js";
import { TLS_1_3 } from "../src/types.js";
import type { ClientHelloConfig } from "../src/types.js";
import { FakeTransport } from "./fake-transport.js";
import { TlsServerSim } from "./server-sim.js";
import { createMockEventProvider, createTestCryptoProvider } from "./test-helpers.js";
import { writeEncryptedRecord } from "../src/connection/record-layer.js";

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

/** Private fields the handshake driver sets; exposed via cast. */
type Internals = {
    applicationSecrets: {
        client: { key: Uint8Array; iv: Uint8Array };
        server: { key: Uint8Array; iv: Uint8Array };
    };
    serverAppSeq: number;
};

/** Build a well-formed NewSessionTicket handshake message. */
function buildNewSessionTicketMessage(opts: {
    readonly ticketAgeAdd?: number;
    readonly ticketNonce?: Uint8Array;
    readonly ticket?: Uint8Array;
    readonly earlyDataMax?: number;
}): Uint8Array {
    const lifetime = 7200;
    const ageAdd = opts.ticketAgeAdd ?? 0x12345678;
    const nonce = opts.ticketNonce ?? new Uint8Array([0x01]);
    const ticket = opts.ticket ?? new Uint8Array(32).fill(0xab);

    // early_data extension (type 42).
    let extensions = new Uint8Array(0);
    if (opts.earlyDataMax !== undefined) {
        extensions = new Uint8Array(8);
        extensions[0] = 0; extensions[1] = 42;
        extensions[2] = 0; extensions[3] = 4;
        extensions[4] = (opts.earlyDataMax >> 24) & 0xff;
        extensions[5] = (opts.earlyDataMax >> 16) & 0xff;
        extensions[6] = (opts.earlyDataMax >> 8) & 0xff;
        extensions[7] = opts.earlyDataMax & 0xff;
    }

    // Body: lifetime(4) + ageAdd(4) + nonce(1+len) + ticket(2+len) + ext(2+len)
    const bodyLen = 4 + 4 + 1 + nonce.length + 2 + ticket.length + 2 + extensions.length;
    const msg = new Uint8Array(4 + bodyLen);
    let o = 0;
    msg[o++] = HandshakeType.NEW_SESSION_TICKET; // type
    msg[o++] = (bodyLen >> 16) & 0xff;
    msg[o++] = (bodyLen >> 8) & 0xff;
    msg[o++] = bodyLen & 0xff;
    // ticket_lifetime
    msg[o++] = (lifetime >> 24) & 0xff;
    msg[o++] = (lifetime >> 16) & 0xff;
    msg[o++] = (lifetime >> 8) & 0xff;
    msg[o++] = lifetime & 0xff;
    // ticket_age_add
    msg[o++] = (ageAdd >>> 24) & 0xff;
    msg[o++] = (ageAdd >>> 16) & 0xff;
    msg[o++] = (ageAdd >>> 8) & 0xff;
    msg[o++] = ageAdd & 0xff;
    // ticket_nonce
    msg[o++] = nonce.length & 0xff;
    msg.set(nonce, o); o += nonce.length;
    // ticket
    msg[o++] = (ticket.length >> 8) & 0xff;
    msg[o++] = ticket.length & 0xff;
    msg.set(ticket, o); o += ticket.length;
    // extensions
    msg[o++] = (extensions.length >> 8) & 0xff;
    msg[o++] = extensions.length & 0xff;
    msg.set(extensions, o);
    return msg;
}

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

describe("NewSessionTicket processing", () => {
    it("stores a parsed ticket + derived PSK in the session cache", async () => {
        const { conn, transport, internals } = await openConnection();
        const ticketBytes = new Uint8Array(32).fill(0xcd);

        // Encrypt a NewSessionTicket under the server application traffic key.
        const nstMsg = buildNewSessionTicketMessage({
            ticketAgeAdd: 0xdeadbeef,
            ticket: ticketBytes,
        });
        writeEncryptedRecord(
            transport, "AES-128-GCM", internals.applicationSecrets.server,
            ContentType.HANDSHAKE, nstMsg, internals.serverAppSeq, crypto,
        );
        const record = transport.written.pop()!;
        transport.readQueue.push(record);

        // read() processes the NewSessionTicket (post-handshake) then loops.
        // It parks waiting for the next record — race it so the test doesn't hang.
        await expect(Promise.race([
            conn.read(),
            new Promise((_r, reject) => setTimeout(() => reject(new Error("parked")), 50)),
        ])).rejects.toThrow("parked");

        // The ticket must have been stored in the session cache.
        const ticket = conn.getResumptionTicket("example.com");
        expect(ticket).toBeDefined();
        expect(ticket!.ticket).toEqual(ticketBytes);
        expect(ticket!.ticketAgeAdd).toBe(0xdeadbeef);
        expect(ticket!.psk.length).toBe(32); // SHA-256 hash length
        expect(ticket!.cipherSuite).toBe("TLS_AES_128_GCM_SHA256");
    });

    it("extracts max_early_data_size from the early_data extension", async () => {
        const { conn, transport, internals } = await openConnection();

        const nstMsg = buildNewSessionTicketMessage({ earlyDataMax: 16384 });
        writeEncryptedRecord(
            transport, "AES-128-GCM", internals.applicationSecrets.server,
            ContentType.HANDSHAKE, nstMsg, internals.serverAppSeq, crypto,
        );
        const record = transport.written.pop()!;
        transport.readQueue.push(record);

        await expect(Promise.race([
            conn.read(),
            new Promise((_r, reject) => setTimeout(() => reject(new Error("parked")), 50)),
        ])).rejects.toThrow("parked");

        const ticket = conn.getResumptionTicket("example.com");
        expect(ticket).toBeDefined();
        expect(ticket!.maxEarlyDataSize).toBe(16384);
    });

    it("returns undefined for a server name with no stored ticket", async () => {
        const { conn } = await openConnection();
        expect(conn.getResumptionTicket("other.com")).toBeUndefined();
    });
});
