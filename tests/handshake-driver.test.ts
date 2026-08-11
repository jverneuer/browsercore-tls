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
import { NobleX25519Backend } from "@browsercore/crypto";
import { connectTls } from "../src/tls.js";
import { TlsHandshakeError } from "../src/errors.js";
import { ContentType } from "../src/record/record.js";
import { TLS_1_2, TLS_1_3 } from "../src/types.js";
import type { ClientHelloConfig } from "../src/types.js";
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

/**
 * Build a raw TLS Alert record (RFC 8446 §6): content type 21 (ALERT),
 * version 0x0303, and a 2-byte payload (alert level + description). Used to
 * simulate a server that rejects the ClientHello with a fatal or warning alert
 * instead of sending a ServerHello — exercising the Alert-parsing branch in
 * runHandshake that surfaces the server's rejection reason.
 */
function buildAlertRecord(level: number, description: number): Uint8Array {
    return new Uint8Array([ContentType.ALERT, 0x03, 0x03, 0x00, 0x02, level, description]);
}

/**
 * A transport that drives the server simulator: when the client writes its
 * ClientHello (a plaintext HANDSHAKE record), the simulator builds the server's
 * full flight and queues it for read(). Subsequent writes (the client's
 * encrypted Finished) are just buffered.
 *
 * For HelloRetryRequest tests, the client writes TWO ClientHello records (the
 * second after receiving the HRR). The transport triggers the sim on every
 * HANDSHAKE write — the sim tracks its own state (first call → HRR, second
 * call → real flight). The client's Finished is APPLICATION_DATA, so it never
 * re-triggers.
 */
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

describe("connectTls full handshake (runHandshake)", () => {
    it("completes the TLS 1.3 handshake and reaches the open state", async () => {
        const sim = new TlsServerSim();
        const transport = new HandshakeTransport(sim);
        const conn = await connectTls({
            transport,
            crypto,
            serverName: "example.com",
            profile: PROFILE,
            events: createMockEventProvider(),
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
        const sim = new TlsServerSim({ x25519Backend: new NobleX25519Backend() });
        const transport = new HandshakeTransport(sim);
        const conn = await connectTls({
            transport,
            crypto,
            serverName: "example.com",
            profile: PROFILE,
            events: createMockEventProvider(),
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
            events: createMockEventProvider(),
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
            events: createMockEventProvider(),
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
                events: createMockEventProvider(),
            }),
        ).rejects.toThrow(TlsHandshakeError);
        // No ClientHello was written — the profile check fires first.
        expect(transport.written.length).toBe(0);
    });

    it("rejects a profile whose key-share groups are all unsupported by the crypto backend", async () => {
        // The driver now offers ALL groups in keyShareGroups (no x25519-only
        // filter). Groups the crypto backend cannot generate (x448, secp521r1,
        // ffdhe*) fail fast in generateKeyShares with a typed handshake error.
        const sim = new TlsServerSim();
        const transport = new HandshakeTransport(sim);
        await expect(
            connectTls({
                transport,
                crypto,
                serverName: "example.com",
                profile: { ...PROFILE, keyShareGroups: ["x448"] },
                events: createMockEventProvider(),
            }),
        ).rejects.toThrow(TlsHandshakeError);
        try {
            await connectTls({
                transport: new HandshakeTransport(new TlsServerSim()),
                serverName: "example.com",
                profile: { ...PROFILE, keyShareGroups: ["x448"] },
                events: createMockEventProvider(),
            });
        } catch (e) {
            expect((e as TlsHandshakeError).cause?.message).toMatch(/not supported by the crypto backend/);
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
            connectTls({ transport, serverName: "example.com", profile: PROFILE, crypto, events: createMockEventProvider() }),
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
            connectTls({ transport, serverName: "example.com", profile: PROFILE, crypto, events: createMockEventProvider() }),
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
            events: createMockEventProvider(),
        });
        expect(conn.peerCertificate).toBeDefined();
        expect(conn.peerCertificate!.commonName).toBe("example.com");
    });

    // -----------------------------------------------------------------------
    // Coalesced-record regression tests (RFC 8446 §5.1).
    //
    // Real TLS 1.3 servers (Cloudflare, nginx, OpenSSL) commonly pack multiple
    // handshake messages into a single encrypted record. The original driver
    // assumed one message per record, so the second call to readEncryptedHandshakeMessage
    // would block on transport.read() waiting for data the server had already sent —
    // causing the 10s timeout at the finished phase.
    // -----------------------------------------------------------------------

    it("completes the handshake when the server coalesces all flight messages into one record", async () => {
        const sim = new TlsServerSim({ recordPacking: "coalesced" });
        const transport = new HandshakeTransport(sim);
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
        expect(conn.peerCertificate!.commonName).toBe("example.com");
    });

    it("completes the handshake when the server partially coalesces (two messages per record)", async () => {
        const sim = new TlsServerSim({ recordPacking: "partial" });
        const transport = new HandshakeTransport(sim);
        const conn = await connectTls({
            transport,
            crypto,
            serverName: "example.com",
            profile: PROFILE,
            events: createMockEventProvider(),
        });
        expect(conn.state.state).toBe("open");
        expect(conn.cipherSuite).toBe("TLS_AES_128_GCM_SHA256");
    });

    it("completes a coalesced handshake with ALPN and injected X25519 backend", async () => {
        const sim = new TlsServerSim({
            recordPacking: "coalesced",
            alpn: "h2",
            x25519Backend: new NobleX25519Backend(),
        });
        const transport = new HandshakeTransport(sim);
        const conn = await connectTls({
            transport,
            crypto,
            serverName: "example.com",
            profile: { ...PROFILE, alpnProtocols: ["h2", "http/1.1"] },
            events: createMockEventProvider(),
        });
        expect(conn.state.state).toBe("open");
        expect(conn.alpnProtocol).toBe("h2");
    });

    // -----------------------------------------------------------------------
    // CertificateVerify verification (RFC 8446 §4.4.3).
    //
    // The server sim now generates a REAL ECDSA P-256 signature over the
    // transcript hash. These tests confirm the client verifies it: a valid
    // signature lets the handshake proceed, while a tampered signature causes
    // an immediate abort at the certificate_verify phase.
    // -----------------------------------------------------------------------

    it("verifies the CertificateVerify signature against the leaf cert public key (happy path)", async () => {
        // The default sim generates a real signature, so every handshake that
        // reaches the open state implicitly passes CertificateVerify
        // verification. This test makes that expectation explicit.
        const sim = new TlsServerSim();
        const transport = new HandshakeTransport(sim);
        const conn = await connectTls({
            transport,
            crypto,
            serverName: "example.com",
            profile: PROFILE,
            events: createMockEventProvider(),
        });
        expect(conn.state.state).toBe("open");
    });

    it("rejects a tampered CertificateVerify signature with a certificate_verify error", async () => {
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
            expect.unreachable("expected a CertificateVerify verification failure");
        } catch (e) {
            const err = e as TlsHandshakeError;
            expect(err).toBeInstanceOf(TlsHandshakeError);
            expect(err.phase).toBe("certificate_verify");
            expect(err.cause?.message).toMatch(/does not match the leaf certificate public key/);
        }
    });

    it("rejects a tampered CertificateVerify in a coalesced flight", async () => {
        // With coalesced packing, the corruption is inside a single encrypted
        // record containing EE + Cert + CV + Finished. The AEAD decrypt still
        // succeeds (corruption is in the plaintext), but the signature check
        // fails — confirming verification works regardless of record packing.
        const sim = new TlsServerSim({
            recordPacking: "coalesced",
            tamperCertificateVerify: true,
        });
        const transport = new HandshakeTransport(sim);
        await expect(
            connectTls({
                transport,
                crypto,
                serverName: "example.com",
                profile: PROFILE,
                events: createMockEventProvider(),
            }),
        ).rejects.toThrow(/certificate_verify/);
    });

    // -----------------------------------------------------------------------
    // Alert-parsing coverage (RFC 8446 §6).
    //
    // When the server rejects the ClientHello it sends a TLS Alert record
    // (content type 21) instead of a ServerHello. The handshake driver parses
    // the two-byte Alert payload and includes the human-readable level and
    // description in the error message so the rejection reason is actionable.
    // These tests exercise every branch of that parsing path.
    // -----------------------------------------------------------------------

    it("surfaces a fatal decode_error alert in the rejection message", async () => {
        // Server sends a fatal Alert: level 2, decode_error (50). The driver
        // must parse the Alert and include "decode_error" + "fatal" in the
        // thrown TlsHandshakeError's cause message.
        const sim = new TlsServerSim();
        const transport = new HandshakeTransport(sim);
        sim.onClientHello = (rec: Uint8Array) => {
            void rec; // ClientHello is consumed only to trigger the response queue
            sim.responses = [buildAlertRecord(2, 50)];
        };
        await expect(
            connectTls({ transport, serverName: "example.com", profile: PROFILE, crypto, events: createMockEventProvider() }),
        ).rejects.toThrow(/decode_error/);
    });

    it("surfaces a warning handshake_failure alert in the rejection message", async () => {
        // Server sends a warning Alert: level 1, handshake_failure (40). The
        // driver must include "handshake_failure" + "warning" in the message —
        // exercising the level===1 ternary branch (distinct from fatal===2).
        const sim = new TlsServerSim();
        const transport = new HandshakeTransport(sim);
        sim.onClientHello = (rec: Uint8Array) => {
            void rec;
            sim.responses = [buildAlertRecord(1, 40)];
        };
        await expect(
            connectTls({ transport, serverName: "example.com", profile: PROFILE, crypto, events: createMockEventProvider() }),
        ).rejects.toThrow(/handshake_failure/);
    });

    it("reports a generic handshake-record error for an unexpected content type", async () => {
        // A content type that is neither Alert (21) nor Handshake (22) — e.g.
        // APPLICATION_DATA (23) — must produce the generic "expected handshake
        // record" error rather than attempting Alert parsing.
        const sim = new TlsServerSim();
        const transport = new HandshakeTransport(sim);
        sim.onClientHello = (rec: Uint8Array) => {
            void rec;
            // APPLICATION_DATA record with a single zero-length fragment.
            sim.responses = [new Uint8Array([ContentType.APPLICATION_DATA, 0x03, 0x03, 0x00, 0x00])];
        };
        await expect(
            connectTls({ transport, serverName: "example.com", profile: PROFILE, crypto, events: createMockEventProvider() }),
        ).rejects.toThrow(/expected handshake record/);
    });
});
