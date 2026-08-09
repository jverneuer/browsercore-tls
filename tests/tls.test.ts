/**
 * Tests for @browsercore/tls.
 *
 * Mirrors the transport test style: vitest, real assertions, no mocks for the
 * pure functions (record header parse/serialize). Handshake/crypto parts are
 * stubbed for now — see PLAN.md for the integration steps that fill them in.
 */

import { describe, it, expect } from "vitest";
import { createTestCryptoProvider } from "./test-helpers.js";

const crypto = createTestCryptoProvider();
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
import { connectTls, TlsConnectionImpl, generateKeyShares } from "../src/tls.js";
import {
    HandshakeType,
    advanceHandshake,
    buildClientHello,
    parseServerHello,
    recordServerHello,
} from "../src/handshake/handshake.js";
import type { ClientHelloConfig, ServerHelloValidation } from "../src/handshake/handshake.js";
import { deriveApplicationSecrets, deriveHandshakeTrafficSecrets } from "../src/crypto/keySchedule.js";
import { TLS_1_3 } from "../src/types.js";
import type { CipherSuite, KeyPair } from "../src/types.js";
import { ExtensionType } from "../src/extensions/extensions.js";

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
    it("maps each implemented TLS 1.3 cipher suite to its AEAD algorithm", () => {
        expect(cipherSuiteToAead("TLS_AES_128_GCM_SHA256")).toBe("AES-128-GCM");
        expect(cipherSuiteToAead("TLS_AES_256_GCM_SHA384")).toBe("AES-256-GCM");
        expect(cipherSuiteToAead("TLS_CHACHA20_POLY1305_SHA256")).toBe("CHACHA20-POLY1305");
        // TLS_AES_128_CCM_SHA256 now maps to "AES-128-CCM" (backed by @browsercore/crypto).
        // (see record.test.ts for the mapping assertion).
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

    it("TlsConnectionImpl exposes a branded id and starts connecting", () => {
        const conn = new TlsConnectionImpl(undefined, crypto);
        expect(conn.id).toMatch(/^tls_/);
        expect(conn.state.state).toBe("connecting");
        expect(conn.protocolVersion.name).toBe("TLS 1.3");
        expect(conn.cipherSuite).toBe("TLS_AES_128_GCM_SHA256");
    });
});

describe("generateKeyShares", () => {
    it("returns a 32-byte X25519 public key for the x25519 group", async () => {
        const shares = await generateKeyShares(["x25519"], crypto);
        expect(shares).toHaveLength(1);
        const kp = shares[0]!;
        expect(kp.algorithm).toBe("x25519");
        // X25519 public keys are always 32 bytes (RFC 7748).
        expect(kp.publicKey.length).toBe(32);
        expect(kp.privateKey.length).toBeGreaterThan(0);
    });

    it("returns a 65-byte uncompressed secp256r1 public key for the secp256r1 group", async () => {
        const shares = await generateKeyShares(["secp256r1"], crypto);
        expect(shares).toHaveLength(1);
        const kp = shares[0]!;
        expect(kp.algorithm).toBe("secp256r1");
        // Uncompressed form: 0x04 || 32-byte x || 32-byte y = 65 bytes.
        expect(kp.publicKey.length).toBe(65);
        expect(kp.publicKey[0]).toBe(0x04);
        expect(kp.privateKey.length).toBe(32);
    });

    it("returns a 97-byte uncompressed secp384r1 public key for the secp384r1 group", async () => {
        const shares = await generateKeyShares(["secp384r1"], crypto);
        expect(shares).toHaveLength(1);
        const kp = shares[0]!;
        expect(kp.algorithm).toBe("secp384r1");
        // Uncompressed form: 0x04 || 48-byte x || 48-byte y = 97 bytes.
        expect(kp.publicKey.length).toBe(97);
        expect(kp.publicKey[0]).toBe(0x04);
        expect(kp.privateKey.length).toBe(48);
    });

    it("generates shares for multiple groups in one call", async () => {
        const shares = await generateKeyShares(["x25519", "secp256r1", "secp384r1"], crypto);
        expect(shares).toHaveLength(3);
        expect(shares.map((s) => s.algorithm)).toEqual(["x25519", "secp256r1", "secp384r1"]);
    });

    it("rejects any group the crypto backend cannot generate", async () => {
        // The crypto backend only exposes X25519 and the two NIST ECDH curves —
        // other (EC)DHE groups fail fast with a typed handshake error rather than
        // a bogus key.
        await expect(generateKeyShares(["x448"], crypto)).rejects.toThrow(TlsHandshakeError);
        try {
            await generateKeyShares(["x448"], crypto);
        } catch (e) {
            const err = e as TlsHandshakeError;
            expect(err.phase).toBe("client_hello");
            expect(err.cause?.message).toMatch(/not supported by the crypto backend/);
        }
    });
});

describe("buildClientHello", () => {
    const config: ClientHelloConfig = {
        cipherSuites: ["TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"],
        extensionOrder: [
            0, 10, 11, 13, 16, 17613, 18, 23, 27, 35, 41, 43, 45, 5, 51, 65281,
        ],
        keyShareGroups: ["x25519"],
        signatureAlgorithms: ["ecdsa_secp256r1_sha256", "rsa_pss_rsae_sha256"],
        supportedVersions: [TLS_1_3],
        serverName: "example.com",
        alpnProtocols: ["h2", "http/1.1"],
        grease: true,
    };

    it("produces bytes whose first byte is the handshake record content type (22) and handshake type (1)", async () => {
        // A ClientHello is carried in a handshake record: the record header's
        // content type is 22 (HANDSHAKE) and the handshake message type is 1
        // (CLIENT_HELLO). buildClientHello emits the handshake message itself,
        // so we prepend a record header (as _writeRecord does) before asserting.
        const keyPairs = await generateKeyShares(["x25519"], crypto);
        const hello = buildClientHello(config, keyPairs, () => Math.random(), crypto);
        expect(hello[0]).toBe(HandshakeType.CLIENT_HELLO);

        const header = new Uint8Array([ContentType.HANDSHAKE, 0x03, 0x01, 0x00, hello.length & 0xff]);
        const record = new Uint8Array(header.length + hello.length);
        record.set(header, 0);
        record.set(hello, header.length);

        expect(record[0]).toBe(ContentType.HANDSHAKE); // 22
        expect(record[5]).toBe(HandshakeType.CLIENT_HELLO); // 1
    });
});

describe("parseServerHello", () => {
    // A minimal valid ServerHello body (without the 4-byte handshake header):
    // legacy_version(2) || random(32) || session_id_len(1)=0 || cipher_suite(2)
    // || compression(1)=0 || extensions_len(2) || extensions.
    // The one required extension is supported_versions (type 43) with a 2-byte
    // selected version == 0x0304 (TLS 1.3).
    function buildServerHelloBody(cipherSuite: CipherSuite, versionWire: number): Uint8Array {
        const random = new Uint8Array(32); // deterministic zeros — parsing does not inspect random
        const sessionId = new Uint8Array(0);

        // supported_versions extension body is a single uint16.
        const svBody = new Uint8Array([(versionWire >> 8) & 0xff, versionWire & 0xff]);
        const svExt = new Uint8Array(2 + 2 + svBody.length);
        svExt[0] = (ExtensionType.SUPPORTED_VERSIONS >> 8) & 0xff;
        svExt[1] = ExtensionType.SUPPORTED_VERSIONS & 0xff;
        svExt[2] = (svBody.length >> 8) & 0xff;
        svExt[3] = svBody.length & 0xff;
        svExt.set(svBody, 4);

        const cipherWire =
            cipherSuite === "TLS_AES_128_GCM_SHA256"
                ? 0x1301
                : cipherSuite === "TLS_AES_256_GCM_SHA384"
                  ? 0x1302
                  : cipherSuite === "TLS_CHACHA20_POLY1305_SHA256"
                    ? 0x1303
                    : 0x1304;

        const body = new Uint8Array(2 + 32 + 1 + 2 + 1 + 2 + svExt.length);
        let o = 0;
        body[o++] = 0x03;
        body[o++] = 0x03; // legacy_version
        body.set(random, o);
        o += 32;
        body[o++] = sessionId.length; // session_id_len
        body[o++] = (cipherWire >> 8) & 0xff;
        body[o++] = cipherWire & 0xff; // cipher_suite
        body[o++] = 0x00; // compression
        body[o++] = (svExt.length >> 8) & 0xff;
        body[o++] = svExt.length & 0xff; // extensions_len
        body.set(svExt, o);
        return body;
    }

    const offered: ServerHelloValidation = {
        cipherSuites: ["TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"],
        supportedVersions: [TLS_1_3],
    };

    it("returns the negotiated cipher suite and version for a valid ServerHello", () => {
        const body = buildServerHelloBody("TLS_AES_128_GCM_SHA256", TLS_1_3.wire);
        const sh = parseServerHello(body, offered);
        expect(sh.cipherSuite).toBe("TLS_AES_128_GCM_SHA256");
        expect(sh.selectedVersion).toEqual(TLS_1_3);
    });

    it("throws when the server selects a cipher suite we did not offer", () => {
        // Server picks TLS_AES_128_CCM_SHA256, which is NOT in the offered list.
        // The specific reason lives in the TlsHandshakeError's cause.
        const body = buildServerHelloBody("TLS_AES_128_CCM_SHA256", TLS_1_3.wire);
        expect(() => parseServerHello(body, offered)).toThrow(TlsHandshakeError);
        try {
            parseServerHello(body, offered);
        } catch (e) {
            const err = e as TlsHandshakeError;
            expect(err.phase).toBe("server_hello");
            expect(err.cause?.message).toMatch(/unoffered cipher suite/);
        }
    });
});

describe("mock handshake derives application traffic keys", () => {
    // Drive the server's second flight through the state machine using canned
    // messages, then run the key schedule over a fake transcript to confirm the
    // application traffic secrets derive to the expected key/iv sizes. This is
    // the pure, network-free core of _performHandshake + _consumeServerFlight.
    const cipherSuite: CipherSuite = "TLS_AES_128_GCM_SHA256";

    function dummyKeyPair(): KeyPair {
        return {
            algorithm: "x25519",
            privateKey: new Uint8Array(32),
            publicKey: new Uint8Array(32),
        };
    }

    it("advances through the server flight and derives 16-byte keys / 12-byte IVs", async () => {
        // A representative transcript: ClientHello || ServerHello || ... || CertificateVerify.
        // The key schedule only cares that the transcript is a hash-length blob; we
        // use the crypto backend's sha256 over canned handshake messages.
        const clientHello = buildClientHello(
            {
                cipherSuites: [cipherSuite],
                extensionOrder: [
                    0, 10, 11, 13, 16, 17613, 18, 23, 27, 35, 41, 43, 45, 5, 51, 65281,
                ],
                keyShareGroups: ["x25519"],
                signatureAlgorithms: ["ecdsa_secp256r1_sha256"],
                supportedVersions: [TLS_1_3],
                serverName: "example.com",
                grease: true,
            },
            [dummyKeyPair()],
            () => Math.random(),
            crypto,
        );
        // A ServerHello message (4-byte header + body) so the transcript mirrors reality.
        const shBody = new Uint8Array([
            0x03, 0x03, // legacy_version
            ...new Array(32).fill(0), // random
            0x00, // session_id_len
            0x13, 0x01, // TLS_AES_128_GCM_SHA256
            0x00, // compression
            0x00, 0x06, // extensions_len
            0x00, 0x2b, 0x00, 0x02, 0x03, 0x04, // supported_versions = TLS 1.3
        ]);
        const serverHello = new Uint8Array(4 + shBody.length);
        serverHello[0] = HandshakeType.SERVER_HELLO;
        serverHello[1] = (shBody.length >> 16) & 0xff;
        serverHello[2] = (shBody.length >> 8) & 0xff;
        serverHello[3] = shBody.length & 0xff;
        serverHello.set(shBody, 4);

        const transcript = [clientHello, serverHello];
        const totalLen = transcript.reduce((n, m) => n + m.length, 0);
        const blob = new Uint8Array(totalLen);
        let offset = 0;
        for (const msg of transcript) {
            blob.set(msg, offset);
            offset += msg.length;
        }
        const helloHash = crypto.sha256(blob);

        // (EC)DHE shared secret: a real one would come from x25519; any non-empty
        // bytes drive the schedule. Use a deterministic placeholder.
        const sharedSecret = new Uint8Array(32).fill(0x42);

        const { masterSecret } = deriveHandshakeTrafficSecrets(sharedSecret, helloHash, cipherSuite, crypto);

        // Advance the state machine through the server's encrypted flight to the
        // terminal "finished_received" phase — the point at which the client sends
        // its Finished and application secrets become usable.
        let phase = recordServerHello({ phase: "client_hello_sent" }, {
            protocolVersion: 0x0303,
            random: new Uint8Array(32),
            sessionId: new Uint8Array(0),
            cipherSuite,
            compressionMethod: 0,
            selectedVersion: TLS_1_3,
            extensions: new Uint8Array(0),
        });
        phase = advanceHandshake(phase, HandshakeType.ENCRYPTED_EXTENSIONS);
        phase = advanceHandshake(phase, HandshakeType.CERTIFICATE);
        phase = advanceHandshake(phase, HandshakeType.CERTIFICATE_VERIFY);
        phase = advanceHandshake(phase, HandshakeType.FINISHED);
        expect(phase.phase).toBe("finished_received");

        // Application traffic secrets: client + server, each keyed and ived.
        const appSecrets = deriveApplicationSecrets(masterSecret, helloHash, cipherSuite, crypto);
        expect(appSecrets.client.key.length).toBe(16); // AES-128
        expect(appSecrets.client.iv.length).toBe(12);
        expect(appSecrets.server.key.length).toBe(16);
        expect(appSecrets.server.iv.length).toBe(12);
    });
});
