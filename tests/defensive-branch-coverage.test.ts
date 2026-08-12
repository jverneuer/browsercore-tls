/**
 * Coverage tests for defensive error branches across the connection layer.
 *
 * Each branch below is a runtime guard required by noUncheckedIndexedAccess
 * or by protocol-level invariant checks. They are exercised by constructing
 * malformed inputs or manipulating the server simulator's output.
 *
 * Branches covered:
 * - record-layer.ts:109 — readRawRecord: header.raw[0] === undefined (empty raw)
 * - handshake-driver.ts:248 — second ServerHello after HRR is not HANDSHAKE type
 * - handshake-driver.ts:377 — decrypted record contained no handshake messages
 * - handshake-driver.ts:420 — CertificateVerify received before Certificate consumed
 * - handshake-driver.ts:433 — server sends CompressedCertificate (type 25) instead of Certificate
 * - handshake-driver.ts:168 — profile keyShareGroups yields no supported key shares
 * - handshake-driver.ts:445 — unexpected handshake type in the Certificate phase
 */

import { describe, it, expect, vi } from "vitest";
import { createTestCryptoProvider, createMockEventProvider } from "./test-helpers.js";
import { FakeTransport } from "./fake-transport.js";
import { connectTls } from "../src/tls.js";
import { TlsHandshakeError, TlsDecryptError } from "../src/errors.js";
import { ContentType, serializeRecordHeader, encryptRecord } from "../src/record/record.js";
import { TLS_1_3 } from "../src/types.js";
import type { ClientHelloConfig } from "../src/types.js";
import { TlsServerSim } from "./server-sim.js";
import { readRawRecord, xorNonce, AEAD_TAG_LENGTH } from "../src/connection/record-layer.js";
import * as handshakeMessages from "../src/connection/handshake-messages.js";
import * as keySchedule from "../src/crypto/keySchedule.js";

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

// ---------------------------------------------------------------------------
// record-layer.ts:109 — readRawRecord with missing content type byte
// ---------------------------------------------------------------------------

describe("readRawRecord — missing content type byte (header.raw empty)", () => {
    it("throws TlsDecryptError when header.raw has no bytes", async () => {
        // Provide a read buffer with enough bytes so ensureBytes does not call
        // transport.read(). The header's raw field is a zero-length Uint8Array,
        // so header.raw[0] is undefined — triggering the defensive guard.
        const transport = new FakeTransport();
        const readBuffer = new Uint8Array(10);
        await expect(
            readRawRecord(readBuffer, transport, { raw: new Uint8Array(0), length: 0 }),
        ).rejects.toThrow(TlsDecryptError);
    });
});

// ---------------------------------------------------------------------------
// handshake-driver.ts:248 — non-HANDSHAKE record after HelloRetryRequest
// ---------------------------------------------------------------------------

/**
 * Transport that drives the server simulator on every HANDSHAKE write. Used for
 * the HRR flow where the client sends two ClientHellos.
 */
class HrrTransport extends FakeTransport {
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

describe("runHandshake — non-handshake record for real ServerHello after HRR", () => {
    it("throws TlsHandshakeError when the post-HRR ServerHello is APPLICATION_DATA", async () => {
        const sim = new TlsServerSim({ helloRetryRequest: { selectedGroup: "x25519" } });

        // Intercept the second onClientHello call (the one that generates the
        // real flight) and flip the ServerHello record's content type from
        // HANDSHAKE (22) to APPLICATION_DATA (23). The client expects a
        // HANDSHAKE record and must reject at handshake-driver.ts:248.
        let callCount = 0;
        const orig = sim.onClientHello.bind(sim);
        sim.onClientHello = (rec: Uint8Array): void => {
            callCount++;
            orig(rec);
            if (callCount === 2) {
                const sh = sim.responses[0]!;
                sim.responses[0] = new Uint8Array([ContentType.APPLICATION_DATA, ...sh.subarray(1)]);
            }
        };

        const transport = new HrrTransport(sim);
        await expect(
            connectTls({
                transport,
                crypto,
                serverName: "example.com",
                profile: PROFILE,
                events: createMockEventProvider(),
            }),
        ).rejects.toThrow(TlsHandshakeError);
    });
});

// ---------------------------------------------------------------------------
// handshake-driver.ts:377 — decrypted record with no handshake messages
// ---------------------------------------------------------------------------

/**
 * Spy on deriveTrafficSecrets to capture the server handshake traffic key/iv.
 * The server simulator calls deriveTrafficSecrets for its server-side traffic
 * during onClientHello — before the client derives its own. So the FIRST call
 * captured by the spy is the server's traffic key, which we reuse to encrypt a
 * custom record whose plaintext is just the inner content type byte.
 */
function captureServerTraffic(): {
    spy: ReturnType<typeof vi.spyOn>;
    get: () => { key: Uint8Array; iv: Uint8Array } | undefined;
} {
    const orig = keySchedule.deriveTrafficSecrets;
    let captured: { key: Uint8Array; iv: Uint8Array } | undefined;
    const spy = vi.spyOn(keySchedule, "deriveTrafficSecrets");
    spy.mockImplementation((...args: Parameters<typeof orig>) => {
        const result = orig(...args);
        if (captured === undefined) captured = result;
        return result;
    });
    return { spy, get: () => captured };
}

describe("runHandshake — decrypted record with no handshake messages", () => {
    it("throws when the decrypted record contains no handshake messages", async () => {
        const { spy, get: getTraffic } = captureServerTraffic();

        const sim = new TlsServerSim();
        const transport = new FakeTransport();

        // Override write: trigger the sim (which populates the spy's captured
        // traffic key via deriveTrafficSecrets), then replace the encrypted
        // flight with a single record whose plaintext is just [22] (HANDSHAKE
        // inner content type byte). After AEAD decryption + inner-type stripping,
        // the content is empty → splitHandshakeMessages returns [].
        transport.write = async (data: Uint8Array): Promise<void> => {
            transport.written.push(data);
            if (data.length > 0 && data[0] === ContentType.HANDSHAKE) {
                sim.onClientHello(data);
                const traffic = getTraffic();
                if (traffic !== undefined) {
                    const shRecord = sim.responses[0]!;
                    const plaintext = new Uint8Array([ContentType.HANDSHAKE]);
                    const header = serializeRecordHeader(
                        ContentType.APPLICATION_DATA,
                        plaintext.length + AEAD_TAG_LENGTH,
                    );
                    const nonce = xorNonce(traffic.iv, 0);
                    const ciphertext = encryptRecord(
                        plaintext, traffic.key, nonce, header, "AES-128-GCM", crypto,
                    );
                    const emptyRecord = new Uint8Array(header.length + ciphertext.length);
                    emptyRecord.set(header, 0);
                    emptyRecord.set(ciphertext, header.length);
                    transport.readQueue.push(shRecord);
                    transport.readQueue.push(emptyRecord);
                }
            }
        };

        await expect(
            connectTls({
                transport,
                crypto,
                serverName: "example.com",
                profile: PROFILE,
                events: createMockEventProvider(),
            }),
        ).rejects.toThrow(/no handshake messages/);

        spy.mockRestore();
    });
});

// ---------------------------------------------------------------------------
// handshake-driver.ts:420 — CertificateVerify before Certificate consumed
// ---------------------------------------------------------------------------

/**
 * Transport that drives the server simulator on the first HANDSHAKE write.
 */
class SimTransport extends FakeTransport {
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

describe("runHandshake — CertificateVerify before Certificate consumed", () => {
    it("throws when peerCertificate is undefined at CertificateVerify", async () => {
        // Mock validateCertificateChain so it returns a chain whose leaf is
        // undefined. This makes ctx.peerCertificate undefined after the
        // Certificate step, so the defensive guard at line 420 fires when the
        // driver reaches CertificateVerify processing.
        const origValidate = handshakeMessages.validateCertificateChain;
        const spy = vi.spyOn(handshakeMessages, "validateCertificateChain");
        spy.mockImplementation(async (...args: Parameters<typeof origValidate>) => {
            const chain = await origValidate(...args);
            return { ...chain, leaf: undefined } as typeof chain;
        });

        const sim = new TlsServerSim();
        const transport = new SimTransport(sim);

        await expect(
            connectTls({
                transport,
                crypto,
                serverName: "example.com",
                profile: PROFILE,
                events: createMockEventProvider(),
            }),
        ).rejects.toThrow(/CertificateVerify received before a Certificate/);

        spy.mockRestore();
    });
});

// ---------------------------------------------------------------------------
// handshake-driver.ts:433 — server sends CompressedCertificate (type 25)
// ---------------------------------------------------------------------------

describe("runHandshake — server sends CompressedCertificate (RFC 8879, type 25)", () => {
    it("throws an actionable error mentioning compress_certificate (ext 27)", async () => {
        const sim = new TlsServerSim({ sendCompressedCertificate: true });
        const transport = new SimTransport(sim);

        await expect(
            connectTls({
                transport,
                crypto,
                serverName: "example.com",
                profile: PROFILE,
                events: createMockEventProvider(),
            }),
        ).rejects.toThrow(/CompressedCertificate.*RFC 8879/);
    });
});

// ---------------------------------------------------------------------------
// handshake-driver.ts:168 — profile with no supported key share groups
// ---------------------------------------------------------------------------

describe("runHandshake — profile keyShareGroups yields no supported key shares", () => {
    it("throws when generateKeyShares returns an empty list", async () => {
        // A profile whose keyShareGroups contains no recognized group causes
        // generateKeyShares to return [] — the driver must reject before building
        // the ClientHello with an actionable error.
        const sim = new TlsServerSim();
        const transport = new SimTransport(sim);

        await expect(
            connectTls({
                transport,
                crypto,
                serverName: "example.com",
                profile: { ...PROFILE, keyShareGroups: [] },
                events: createMockEventProvider(),
            }),
        ).rejects.toThrow(/no supported key share groups/);
    });
});

// ---------------------------------------------------------------------------
// handshake-driver.ts:445 — unexpected handshake type in Certificate phase
// ---------------------------------------------------------------------------

describe("runHandshake — unexpected handshake type in Certificate phase", () => {
    it("throws 'expected Certificate' for a type that is neither 11 nor 25", async () => {
        // The server sends a handshake type (99) that is neither Certificate
        // (11) nor CompressedCertificate (25) in the Certificate slot. The
        // driver must reject it with a clear "expected Certificate" error.
        const sim = new TlsServerSim({ certHandshakeType: 99 });
        const transport = new SimTransport(sim);

        await expect(
            connectTls({
                transport,
                crypto,
                serverName: "example.com",
                profile: PROFILE,
                events: createMockEventProvider(),
            }),
        ).rejects.toThrow(/expected Certificate/);
    });
});
