/**
 * Tests for @browsercore/tls handshake protocol (RFC 8446 §4).
 *
 * The pure parts of handshake.ts: the handshake state machine (advanceHandshake,
 * recordServerHello, completeHandshake), the predicate helpers (isKeyShareGroup,
 * isTls13), the cipher-suite wire codec, and edge cases in buildClientHello.
 */

import { describe, it, expect } from "vitest";
import { createTestCryptoProvider } from "./test-helpers.js";

const crypto = createTestCryptoProvider();
import {
    HandshakeType,
    advanceHandshake,
    recordServerHello,
    completeHandshake,
    isKeyShareGroup,
    isTls13,
    buildClientHello,
    parseServerHello,
} from "../src/handshake/handshake.js";
import type { HandshakePhase, ServerHello, ServerHelloValidation } from "../src/handshake/handshake.js";
import { TlsHandshakeError } from "../src/errors.js";
import { ExtensionType } from "../src/extensions/extensions.js";
import { TLS_1_2, TLS_1_3 } from "../src/types.js";
import type { CipherSuite, ClientHelloConfig, KeyPair, ProtocolVersion } from "../src/types.js";

describe("isKeyShareGroup", () => {
    it("returns true for every (EC)DHE group the crypto backend supports", () => {
        expect(isKeyShareGroup("secp256r1")).toBe(true);
        expect(isKeyShareGroup("secp384r1")).toBe(true);
        expect(isKeyShareGroup("x25519")).toBe(true);
    });

    it("returns false for (EC)DHE groups the crypto backend does not support", () => {
        // x448, secp521r1, FFDHE groups, and the post-quantum hybrids are
        // valid wire groups but the crypto backend does not implement their
        // key exchange, so they are not usable for key share.
        expect(isKeyShareGroup("x448")).toBe(false);
        expect(isKeyShareGroup("secp521r1")).toBe(false);
        expect(isKeyShareGroup("ffdhe2048")).toBe(false);
        expect(isKeyShareGroup("ffdhe3072")).toBe(false);
        expect(isKeyShareGroup("X25519MLKEM768")).toBe(false);
        expect(isKeyShareGroup("X25519Kyber768")).toBe(false);
    });
});

describe("isTls13", () => {
    it("is true only for TLS 1.3", () => {
        expect(isTls13(TLS_1_3)).toBe(true);
        expect(isTls13(TLS_1_2)).toBe(false);
    });
});

describe("recordServerHello + completeHandshake", () => {
    const hello: ServerHello = {
        protocolVersion: 0x0303,
        random: new Uint8Array(32),
        sessionId: new Uint8Array(0),
        cipherSuite: "TLS_AES_128_GCM_SHA256",
        compressionMethod: 0,
        selectedVersion: TLS_1_3,
        extensions: new Uint8Array(0),
    };

    it("recordServerHello attaches the ServerHello and transitions the phase", () => {
        const phase = recordServerHello({ phase: "client_hello_sent" }, hello);
        expect(phase.phase).toBe("server_hello_received");
        if (phase.phase === "server_hello_received") {
            expect(phase.serverHello).toBe(hello);
        }
    });

    it("completeHandshake moves any non-terminal phase to complete", () => {
        expect(completeHandshake({ phase: "finished_received" }).phase).toBe("complete");
        expect(completeHandshake({ phase: "certificate_received" }).phase).toBe("complete");
    });
});

describe("advanceHandshake state machine", () => {
    const hello: ServerHello = {
        protocolVersion: 0x0303,
        random: new Uint8Array(32),
        sessionId: new Uint8Array(0),
        cipherSuite: "TLS_AES_128_GCM_SHA256",
        compressionMethod: 0,
        selectedVersion: TLS_1_3,
        extensions: new Uint8Array(0),
    };
    const start: HandshakePhase = { phase: "client_hello_sent" };
    const afterSh = recordServerHello(start, hello);

    /** Assert a throw whose CAUSE message matches `re` (the outer message is generic). */
    const throwsCause = (re: RegExp, fn: () => void): void => {
        try {
            fn();
            expect.unreachable("expected a throw");
        } catch (e) {
            const err = e as TlsHandshakeError;
            expect(err).toBeInstanceOf(TlsHandshakeError);
            expect(err.cause?.message).toMatch(re);
        }
    };

    it("rejects a transition out of the start phase", () => {
        throwsCause(/expected client_hello_sent/, () =>
            advanceHandshake({ phase: "start" }, HandshakeType.CLIENT_HELLO),
        );
    });

    it("rejects anything but SERVER_HELLO after client_hello_sent (and directs to recordServerHello)", () => {
        throwsCause(/expected SERVER_HELLO/, () => advanceHandshake(start, HandshakeType.ENCRYPTED_EXTENSIONS));
        // Even the correct type throws: the caller must use recordServerHello instead.
        throwsCause(/recordServerHello/, () => advanceHandshake(start, HandshakeType.SERVER_HELLO));
    });

    it("advances server_hello_received -> encrypted_extensions_received", () => {
        expect(advanceHandshake(afterSh, HandshakeType.ENCRYPTED_EXTENSIONS).phase).toBe(
            "encrypted_extensions_received",
        );
    });

    it("rejects a non-ENCRYPTED_EXTENSIONS message after server_hello_received", () => {
        throwsCause(/expected ENCRYPTED_EXTENSIONS/, () => advanceHandshake(afterSh, HandshakeType.CERTIFICATE));
    });

    it("advances encrypted_extensions_received -> certificate_received", () => {
        const phase = advanceHandshake(afterSh, HandshakeType.ENCRYPTED_EXTENSIONS);
        expect(advanceHandshake(phase, HandshakeType.CERTIFICATE).phase).toBe("certificate_received");
    });

    it("rejects a non-CERTIFICATE message after encrypted_extensions_received", () => {
        const phase = advanceHandshake(afterSh, HandshakeType.ENCRYPTED_EXTENSIONS);
        throwsCause(/expected CERTIFICATE/, () => advanceHandshake(phase, HandshakeType.FINISHED));
    });

    it("advances certificate_received -> certificate_verify_received", () => {
        let phase = advanceHandshake(afterSh, HandshakeType.ENCRYPTED_EXTENSIONS);
        phase = advanceHandshake(phase, HandshakeType.CERTIFICATE);
        expect(advanceHandshake(phase, HandshakeType.CERTIFICATE_VERIFY).phase).toBe(
            "certificate_verify_received",
        );
    });

    it("rejects a non-CERTIFICATE_VERIFY message after certificate_received", () => {
        let phase = advanceHandshake(afterSh, HandshakeType.ENCRYPTED_EXTENSIONS);
        phase = advanceHandshake(phase, HandshakeType.CERTIFICATE);
        throwsCause(/expected CERTIFICATE_VERIFY/, () => advanceHandshake(phase, HandshakeType.FINISHED));
    });

    it("advances certificate_verify_received -> finished_received", () => {
        let phase = advanceHandshake(afterSh, HandshakeType.ENCRYPTED_EXTENSIONS);
        phase = advanceHandshake(phase, HandshakeType.CERTIFICATE);
        phase = advanceHandshake(phase, HandshakeType.CERTIFICATE_VERIFY);
        expect(advanceHandshake(phase, HandshakeType.FINISHED).phase).toBe("finished_received");
    });

    it("rejects a non-FINISHED message after certificate_verify_received", () => {
        let phase = advanceHandshake(afterSh, HandshakeType.ENCRYPTED_EXTENSIONS);
        phase = advanceHandshake(phase, HandshakeType.CERTIFICATE);
        phase = advanceHandshake(phase, HandshakeType.CERTIFICATE_VERIFY);
        throwsCause(/expected FINISHED/, () => advanceHandshake(phase, HandshakeType.KEY_UPDATE));
    });

    it("rejects any transition out of the terminal finished_received phase", () => {
        let phase = advanceHandshake(afterSh, HandshakeType.ENCRYPTED_EXTENSIONS);
        phase = advanceHandshake(phase, HandshakeType.CERTIFICATE);
        phase = advanceHandshake(phase, HandshakeType.CERTIFICATE_VERIFY);
        phase = advanceHandshake(phase, HandshakeType.FINISHED);
        throwsCause(/terminal phase/, () => advanceHandshake(phase, HandshakeType.NEW_SESSION_TICKET));
    });

    it("rejects any transition out of the terminal complete phase", () => {
        const phase = completeHandshake(afterSh);
        throwsCause(/terminal phase/, () => advanceHandshake(phase, HandshakeType.NEW_SESSION_TICKET));
    });

    it("hits the exhaustiveness default for an impossible phase", () => {
        // A phase that is not a member of the HandshakePhase union. The default
        // branch is unreachable by construction; we exercise it at runtime to
        // cover the assertNever guard.
        const bogus = { phase: "not-a-phase" } as unknown as HandshakePhase;
        expect(() => advanceHandshake(bogus, HandshakeType.FINISHED)).toThrow(/Unexpected value/);
    });
});

describe("wireToCipherSuite (invalid value)", () => {
    it("parseServerHello surfaces a TlsHandshakeError for an unknown cipher suite wire value", () => {
        // Build a ServerHello body whose cipher suite is 0x1399 (not a real suite).
        const random = new Uint8Array(32);
        const svBody = new Uint8Array([(TLS_1_3.wire >> 8) & 0xff, TLS_1_3.wire & 0xff]);
        const svExt = new Uint8Array(2 + 2 + svBody.length);
        svExt[0] = (ExtensionType.SUPPORTED_VERSIONS >> 8) & 0xff;
        svExt[1] = ExtensionType.SUPPORTED_VERSIONS & 0xff;
        svExt[2] = (svBody.length >> 8) & 0xff;
        svExt[3] = svBody.length & 0xff;
        svExt.set(svBody, 4);
        const body = new Uint8Array(2 + 32 + 1 + 2 + 1 + 2 + svExt.length);
        let o = 0;
        body[o++] = 0x03;
        body[o++] = 0x03;
        body.set(random, o);
        o += 32;
        body[o++] = 0; // session_id_len
        body[o++] = 0x13;
        body[o++] = 0x99; // unknown cipher suite
        body[o++] = 0; // compression
        body[o++] = (svExt.length >> 8) & 0xff;
        body[o++] = svExt.length & 0xff;
        body.set(svExt, o);

        const offered: ServerHelloValidation = {
            cipherSuites: ["TLS_AES_128_GCM_SHA256"],
            supportedVersions: [TLS_1_3],
        };
        try {
            parseServerHello(body, offered);
            expect.unreachable("expected a throw");
        } catch (e) {
            const err = e as TlsHandshakeError;
            expect(err).toBeInstanceOf(TlsHandshakeError);
            expect(err.cause?.message).toMatch(/unsupported cipher suite/);
        }
    });
});

describe("negotiateVersion errors (via parseServerHello)", () => {
    const offered = {
        cipherSuites: ["TLS_AES_128_GCM_SHA256"],
        supportedVersions: [TLS_1_3],
    };

    /**
     * Build a ServerHello body whose extensions block contains exactly one
     * extension of the given type/data. The cipher suite is always
     * TLS_AES_128_GCM_SHA256 (which IS in `offered`) so parseServerHello reaches
     * negotiateVersion rather than failing earlier at assertCipherSuiteOffered.
     */
    function helloWithExtension(type: number, data: Uint8Array): Uint8Array {
        const random = new Uint8Array(32);
        const ext = new Uint8Array(2 + 2 + data.length);
        ext[0] = (type >> 8) & 0xff;
        ext[1] = type & 0xff;
        ext[2] = (data.length >> 8) & 0xff;
        ext[3] = data.length & 0xff;
        ext.set(data, 4);
        const body = new Uint8Array(2 + 32 + 1 + 2 + 1 + 2 + ext.length);
        let o = 0;
        body[o++] = 0x03;
        body[o++] = 0x03;
        body.set(random, o);
        o += 32;
        body[o++] = 0; // session_id_len
        body[o++] = 0x13;
        body[o++] = 0x01; // TLS_AES_128_GCM_SHA256
        body[o++] = 0; // compression
        body[o++] = (ext.length >> 8) & 0xff;
        body[o++] = ext.length & 0xff;
        body.set(ext, o);
        return body;
    }

    it("throws when the ServerHello lacks the supported_versions extension", () => {
        // Extensions block carries only an ALPN extension (type 16) — no
        // supported_versions (type 43). negotiateVersion must reject this.
        const body = helloWithExtension(ExtensionType.APPLICATION_LAYER_PROTOCOL_NEGOTIATION, new Uint8Array([0x00, 0x03, 0x02, 0x68, 0x32]));
        try {
            parseServerHello(body, offered);
            expect.unreachable("expected a throw");
        } catch (e) {
            const err = e as TlsHandshakeError;
            expect(err).toBeInstanceOf(TlsHandshakeError);
            expect(err.cause?.message).toMatch(/missing required supported_versions/);
        }
    });

    it("throws when the supported_versions extension has an unexpected length", () => {
        // supported_versions for a ServerHello selects exactly one version: a
        // 2-byte body. A 3-byte body is malformed.
        const body = helloWithExtension(ExtensionType.SUPPORTED_VERSIONS, new Uint8Array([0x03, 0x04, 0x00]));
        try {
            parseServerHello(body, offered);
            expect.unreachable("expected a throw");
        } catch (e) {
            const err = e as TlsHandshakeError;
            expect(err).toBeInstanceOf(TlsHandshakeError);
            expect(err.cause?.message).toMatch(/unexpected length/);
        }
    });
});

describe("buildClientHello edge cases", () => {
    async function keyPairs(groups: readonly string[]): Promise<readonly KeyPair[]> {
        const out: KeyPair[] = [];
        for (const g of groups) {
            const kp = crypto.x25519GenerateKeyPair();
            out.push({ algorithm: g as KeyPair["algorithm"], privateKey: kp.secretKey, publicKey: kp.publicKey });
        }
        return out;
    }

    const baseConfig: ClientHelloConfig = {
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

    it("emits an empty ALPN body when alpnProtocols is undefined", async () => {
        const kps = await keyPairs(["x25519"]);
        const hello = buildClientHello(baseConfig, kps, () => Math.random(), crypto);
        // ALPN (type 16) is in the profile's extension order, so the extension
        // IS emitted — but with an empty body when no protocols are configured.
        const extBlock = extractClientHelloExtensions(hello);
        const parsed = parseExtensionsForTest(extBlock);
        const alpn = parsed.find((e) => e.type === ExtensionType.APPLICATION_LAYER_PROTOCOL_NEGOTIATION);
        expect(alpn).toBeDefined();
        expect(alpn!.data.length).toBe(0);
    });

    it("emits an empty ALPN body when alpnProtocols is an empty array", async () => {
        const kps = await keyPairs(["x25519"]);
        const hello = buildClientHello({ ...baseConfig, alpnProtocols: [] }, kps, () => Math.random(), crypto);
        const extBlock = extractClientHelloExtensions(hello);
        const parsed = parseExtensionsForTest(extBlock);
        const alpn = parsed.find((e) => e.type === ExtensionType.APPLICATION_LAYER_PROTOCOL_NEGOTIATION);
        expect(alpn).toBeDefined();
        expect(alpn!.data.length).toBe(0);
    });

    it("emits a populated ALPN body when alpnProtocols is non-empty", async () => {
        const kps = await keyPairs(["x25519"]);
        const hello = buildClientHello({ ...baseConfig, alpnProtocols: ["h2"] }, kps, () => Math.random(), crypto);
        const extBlock = extractClientHelloExtensions(hello);
        const parsed = parseExtensionsForTest(extBlock);
        const alpn = parsed.find((e) => e.type === ExtensionType.APPLICATION_LAYER_PROTOCOL_NEGOTIATION);
        expect(alpn).toBeDefined();
        // Body is non-empty: it carries the "h2" protocol id.
        expect(alpn!.data.length).toBeGreaterThan(0);
    });

    it("builds a ClientHello with an empty serverName", async () => {
        const kps = await keyPairs(["x25519"]);
        const hello = buildClientHello({ ...baseConfig, serverName: "" }, kps, () => Math.random(), crypto);
        expect(hello[0]).toBe(HandshakeType.CLIENT_HELLO);
    });

    it("throws when an ALPN protocol name is empty or exceeds 255 bytes", async () => {
        const kps = await keyPairs(["x25519"]);
        for (const proto of ["", "a".repeat(256)]) {
            try {
                buildClientHello({ ...baseConfig, alpnProtocols: [proto] }, kps, () => Math.random(), crypto);
                expect.unreachable("expected a throw");
            } catch (e) {
                const err = e as TlsHandshakeError;
                expect(err).toBeInstanceOf(TlsHandshakeError);
                expect(err.cause?.message).toMatch(/ALPN protocol must be 1..255/);
            }
        }
    });
});

/**
 * Extract the length-prefixed extensions block from a serialized ClientHello.
 *
 * The message layout is header(4) || version(2) || random(32) || sid_len(1) ||
 * sid || cs_len(2) || cipherSuites || comp_len(1) || compression ||
 * ext_len(2) || extensions. Walking from the front (instead of guessing from the
 * tail) keeps this robust against variable-length cipher-suite / session-id
 * regions. The returned slice INCLUDES the 2-byte length prefix so it can be
 * handed directly to parseExtensionsForTest.
 */
function extractClientHelloExtensions(hello: Uint8Array): Uint8Array {
    let o = 0;
    // Handshake header: msg_type(1) + 24-bit length(3).
    o += 4;
    // legacy_version(2) + random(32).
    o += 2 + 32;
    // session_id: length-prefixed.
    const sidLen = hello[o++]!;
    o += sidLen;
    // cipher_suites: length-prefixed.
    const csLen = (hello[o++]! << 8) | hello[o++]!;
    o += csLen;
    // compression_methods: length-prefixed.
    const compLen = hello[o++]!;
    o += compLen;
    // extensions: length-prefixed. Capture the offset BEFORE consuming ext_len so
    // the returned slice retains the 2-byte prefix parseExtensions expects.
    const extStart = o;
    const extLen = (hello[o++]! << 8) | hello[o++]!;
    return hello.subarray(extStart, extStart + 2 + extLen);
}

/** Minimal extensions parser mirroring extensions.parseExtensions for test isolation. */
function parseExtensionsForTest(buf: Uint8Array): ReadonlyArray<{ type: number; data: Uint8Array }> {
    let o = 0;
    const extensionsLen = (buf[o++]! << 8) | buf[o++]!;
    const end = o + extensionsLen;
    const out: { type: number; data: Uint8Array }[] = [];
    while (o < end) {
        const type = (buf[o++]! << 8) | buf[o++]!;
        const dataLen = (buf[o++]! << 8) | buf[o++]!;
        out.push({ type, data: buf.subarray(o, o + dataLen) });
        o += dataLen;
    }
    return out;
}
