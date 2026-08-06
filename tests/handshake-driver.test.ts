/**
 * Tests for @browsercore/tls handshake driver (runHandshake) via connectTls.
 *
 * Drives the full TLS 1.3 handshake against a simulated server (TlsServerSim),
 * covering the choreography in handshake-driver.ts: ClientHello generation,
 * ServerHello negotiation, (EC)DHE key exchange, server-flight consumption,
 * Finished verification, and application-secret derivation. Also covers the
 * rejection paths (TLS 1.2-only profile, no supported key-share groups).
 */

import { describe, it, expect } from "vitest";
import { crypto, defaultX25519Backend } from "@browsercore/crypto";
import { connectTls } from "../src/tls.js";
import { TlsHandshakeError } from "../src/errors.js";
import { ContentType } from "../src/record/record.js";
import { TLS_1_2, TLS_1_3 } from "../src/types.js";
import type { ClientHelloConfig } from "../src/types.js";
import { FakeTransport } from "./fake-transport.js";
import { TlsServerSim } from "./server-sim.js";

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

/**
 * A transport that drives the server simulator: when the client writes its
 * ClientHello (a plaintext HANDSHAKE record), the simulator builds the server's
 * full flight and queues it for read(). Subsequent writes (the client's
 * encrypted Finished) are just buffered.
 */
class HandshakeTransport extends FakeTransport {
    private sim: TlsServerSim;
    private triggered = false;

    constructor(sim: TlsServerSim) {
        super();
        this.sim = sim;
    }

    public override async write(data: Uint8Array): Promise<void> {
        await super.write(data);
        if (!this.triggered && data.length > 0 && data[0] === ContentType.HANDSHAKE) {
            this.triggered = true;
            this.sim.onClientHello(data);
            for (const resp of this.sim.responses) {
                this.readQueue.push(resp);
            }
        }
    }
}

describe("connectTls full handshake (runHandshake)", () => {
    it("completes the TLS 1.3 handshake and reaches the open state", async () => {
        const sim = new TlsServerSim();
        const transport = new HandshakeTransport(sim);
        const conn = await connectTls({
            transport,
            crypto,
            serverName: "example.com",
            profile: PROFILE,
        });
        expect(conn.state.state).toBe("open");
        expect(conn.cipherSuite).toBe("TLS_AES_128_GCM_SHA256");
        expect(conn.protocolVersion).toEqual(TLS_1_3);

        // The client wrote two things: the ClientHello (plaintext) and the
        // client Finished (encrypted APPLICATION_DATA).
        expect(transport.written.length).toBe(2);
        expect(transport.written[0]![0]).toBe(ContentType.HANDSHAKE);
        expect(transport.written[1]![0]).toBe(ContentType.APPLICATION_DATA);
    });

    it("completes the handshake when the server uses an injected X25519Backend (breaks circular masking)", async () => {
        // The server simulator normally computes the shared secret via the same
        // `crypto.x25519SharedSecret()` the client uses — circular masking that
        // hides X25519 regressions. Injecting an independent backend breaks
        // that: if the client's X25519 drifts from the noble backend's, the
        // derived traffic secrets diverge and the Finished verify fails.
        const sim = new TlsServerSim({ x25519Backend: defaultX25519Backend });
        const transport = new HandshakeTransport(sim);
        const conn = await connectTls({
            transport,
            crypto,
            serverName: "example.com",
            profile: PROFILE,
        });
        expect(conn.state.state).toBe("open");
        expect(conn.cipherSuite).toBe("TLS_AES_128_GCM_SHA256");
        expect(conn.protocolVersion).toEqual(TLS_1_3);
    });

    it("negotiates ALPN when the server offers it in EncryptedExtensions", async () => {
        const sim = new TlsServerSim({ alpn: "h2" });
        const transport = new HandshakeTransport(sim);
        const conn = await connectTls({
            transport,
            crypto,
            serverName: "example.com",
            profile: { ...PROFILE, alpnProtocols: ["h2", "http/1.1"] },
        });
        expect(conn.alpnProtocol).toBe("h2");
    });

    it("leaves alpnProtocol unset when the server sends no ALPN extension", async () => {
        const sim = new TlsServerSim();
        const transport = new HandshakeTransport(sim);
        const conn = await connectTls({
            transport,
            crypto,
            serverName: "example.com",
            profile: PROFILE,
        });
        expect(conn.alpnProtocol).toBeUndefined();
    });

    it("rejects a TLS 1.2-only profile before any I/O", async () => {
        const sim = new TlsServerSim();
        const transport = new HandshakeTransport(sim);
        await expect(
            connectTls({
                transport,
                crypto,
                serverName: "example.com",
                profile: { ...PROFILE, supportedVersions: [TLS_1_2] },
            }),
        ).rejects.toThrow(TlsHandshakeError);
        // No ClientHello was written — the profile check fires first.
        expect(transport.written.length).toBe(0);
    });

    it("rejects a profile whose key-share groups are all unsupported", async () => {
        const sim = new TlsServerSim();
        const transport = new HandshakeTransport(sim);
        await expect(
            connectTls({
                transport,
                crypto,
                serverName: "example.com",
                profile: { ...PROFILE, keyShareGroups: ["secp256r1"] },
            }),
        ).rejects.toThrow(TlsHandshakeError);
        try {
            await connectTls({
                transport: new HandshakeTransport(new TlsServerSim()),
                serverName: "example.com",
                profile: { ...PROFILE, keyShareGroups: ["secp256r1"] },
            });
        } catch (e) {
            expect((e as TlsHandshakeError).cause?.message).toMatch(/no supported key share groups/);
        }
    });

    it("rejects when the server sends a non-handshake record for ServerHello", async () => {
        // A simulator whose ServerHello is actually an application_data record —
        // the client expects a plaintext HANDSHAKE record and must reject.
        const sim = new TlsServerSim();
        const transport = new HandshakeTransport(sim);
        // Patch: replace the first response (ServerHello) with an APPLICATION_DATA record.
        const orig = sim.onClientHello.bind(sim);
        sim.onClientHello = (rec: Uint8Array) => {
            orig(rec);
            const sh = sim.responses[0]!;
            // Flip the outer content type from HANDSHAKE(22) to APPLICATION_DATA(23).
            sim.responses[0] = new Uint8Array([ContentType.APPLICATION_DATA, ...sh.subarray(1)]);
        };
        await expect(
            connectTls({ transport, serverName: "example.com", profile: PROFILE, crypto }),
        ).rejects.toThrow(TlsHandshakeError);
    });

    it("rejects a tampered server Finished (verify_data mismatch)", async () => {
        const sim = new TlsServerSim();
        const transport = new HandshakeTransport(sim);
        // Corrupt the last byte of the Finished's encrypted record so decryption
        // either fails or yields a wrong verify_data.
        const orig = sim.onClientHello.bind(sim);
        sim.onClientHello = (rec: Uint8Array) => {
            orig(rec);
            const finished = sim.responses[4]!; // sh + ee + cert + cv + finished
            finished[finished.length - 1] ^= 0xff;
        };
        await expect(
            connectTls({ transport, serverName: "example.com", profile: PROFILE, crypto }),
        ).rejects.toThrow();
    });

    it("exposes the validated peer leaf certificate", async () => {
        const sim = new TlsServerSim();
        const transport = new HandshakeTransport(sim);
        const conn = await connectTls({
            transport,
            crypto,
            serverName: "example.com",
            profile: PROFILE,
        });
        expect(conn.peerCertificate).toBeDefined();
        expect(conn.peerCertificate!.commonName).toBe("example.com");
    });
});
