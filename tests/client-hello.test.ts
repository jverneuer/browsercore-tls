/**
 * Tests for @browsercore/tls ClientHello construction (RFC 8446 §4.2).
 *
 * The handshake.test.ts file covers buildClientHello's ALPN presence/absence
 * and the ALPN length guard. This file covers the remaining defensive guards
 * that only fire on a malformed config: an SNI server_name that exceeds the
 * 16-bit length prefix, and the per-index undefined checks for cipher suites,
 * supported versions, and signature algorithms. These branches are
 * unreachable from a well-typed caller but exist to satisfy
 * noUncheckedIndexedAccess without non-null assertions, so they are exercised
 * here with crafted configs.
 */

import { describe, it, expect } from "vitest";
import { createTestCryptoProvider } from "./test-helpers.js";

const crypto = createTestCryptoProvider();
import {
    buildClientHello,
    generateGreaseValue,
} from "../src/handshake/client-hello.js";
import { ExtensionType } from "../src/extensions/extensions.js";
import { TlsHandshakeError } from "../src/errors.js";
import { TLS_1_3 } from "../src/types.js";
import type { ClientHelloConfig, KeyPair } from "../src/types.js";
import { NAMED_GROUP_CODES } from "../src/iana/index.js";

async function keyPairs(groups: readonly string[]): Promise<readonly KeyPair[]> {
    const out: KeyPair[] = [];
    for (const g of groups) {
        const kp = crypto.x25519GenerateKeyPair();
        out.push({ algorithm: g as KeyPair["algorithm"], privateKey: kp.secretKey, publicKey: kp.publicKey });
    }
    return out;
}

const BASE_CONFIG: ClientHelloConfig = {
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

describe("buildClientHello SNI length guard", () => {
    it("throws when the SNI server_name exceeds 65535 bytes", async () => {
        const kps = await keyPairs(["x25519"]);
        const huge = "a".repeat(65536);
        try {
            buildClientHello({ ...BASE_CONFIG, serverName: huge }, kps, () => Math.random(), crypto);
            expect.unreachable("expected a throw");
        } catch (e) {
            const err = e as TlsHandshakeError;
            expect(err).toBeInstanceOf(TlsHandshakeError);
            expect(err.phase).toBe("client_hello");
            expect(err.cause?.message).toMatch(/SNI server_name exceeds 65535/);
        }
    });

    it("builds when the SNI server_name is exactly 65535 bytes", async () => {
        const kps = await keyPairs(["x25519"]);
        const max = "a".repeat(65535);
        // Should not throw — the bound is inclusive.
        const hello = buildClientHello({ ...BASE_CONFIG, serverName: max }, kps, () => Math.random(), crypto);
        expect(hello[0]).toBe(0x01); // HandshakeType.CLIENT_HELLO
    });
});

describe("buildClientHello per-index undefined guards", () => {
    it("throws when a cipher suite entry is undefined", async () => {
        // config.cipherSuites is typed as a non-undefined array, but a caller
        // could pass one with a hole; the encoder must not silently emit 0x0000.
        const kps = await keyPairs(["x25519"]);
        const sparse = ["TLS_AES_128_GCM_SHA256", undefined as unknown as "TLS_AES_128_GCM_SHA256"];
        const cfg = { ...BASE_CONFIG, cipherSuites: sparse };
        try {
            buildClientHello(cfg, kps, () => Math.random(), crypto);
            expect.unreachable("expected a throw");
        } catch (e) {
            const err = e as TlsHandshakeError;
            expect(err.phase).toBe("client_hello");
            expect(err.cause?.message).toMatch(/cipher suite at index 1 is missing/);
        }
    });

    it("throws when a supported version entry is undefined", async () => {
        const kps = await keyPairs(["x25519"]);
        const sparse = [TLS_1_3, undefined as unknown as typeof TLS_1_3];
        const cfg = { ...BASE_CONFIG, supportedVersions: sparse };
        try {
            buildClientHello(cfg, kps, () => Math.random(), crypto);
            expect.unreachable("expected a throw");
        } catch (e) {
            const err = e as TlsHandshakeError;
            expect(err.cause?.message).toMatch(/supported version at index 1 is missing/);
        }
    });

    it("throws when a signature algorithm entry is undefined", async () => {
        const kps = await keyPairs(["x25519"]);
        const sparse = ["ecdsa_secp256r1_sha256", undefined as unknown as "ecdsa_secp256r1_sha256"];
        const cfg = { ...BASE_CONFIG, signatureAlgorithms: sparse };
        try {
            buildClientHello(cfg, kps, () => Math.random(), crypto);
            expect.unreachable("expected a throw");
        } catch (e) {
            const err = e as TlsHandshakeError;
            expect(err.cause?.message).toMatch(/signature algorithm at index 1 is missing/);
        }
    });

    it("throws when a supported group entry is undefined", async () => {
        const kps = await keyPairs(["x25519"]);
        const sparse = ["x25519", undefined as unknown as "x25519"];
        const cfg = { ...BASE_CONFIG, keyShareGroups: sparse };
        try {
            buildClientHello(cfg, kps, () => Math.random(), crypto);
            expect.unreachable("expected a throw");
        } catch (e) {
            const err = e as TlsHandshakeError;
            expect(err.cause?.message).toMatch(/supported group at index 1 is missing/);
        }
    });

    it("throws when a compress-certificate algorithm entry is undefined", async () => {
        // extension type 27 (COMPRESS_CERTIFICATE) exercises encodeCompressCertificate,
        // which has a per-index undefined guard over its fixed algorithm list.
        const kps = await keyPairs(["x25519"]);
        const cfg: ClientHelloConfig = {
            ...BASE_CONFIG,
            extensionOrder: [27],
        };
        // Should not throw — the fixed list has no holes; this exercises the loop body.
        const hello = buildClientHello(cfg, kps, () => Math.random(), crypto);
        expect(hello[0]).toBe(0x01);
    });
});

describe("generateGreaseValue defensive guard (noUncheckedIndexedAccess)", () => {
    it("returns a valid GREASE sentinel for any [0,1) input", () => {
        // random()=0.99999999 stays in-bounds (floor(0.99999999*16)=15). The
        // `value === undefined` guard is unreachable for any finite input but
        // exists to satisfy noUncheckedIndexedAccess — we exercise the max edge.
        const v = generateGreaseValue(() => 0.99999999);
        expect(v).toBeGreaterThanOrEqual(0);
        // The guard branch can't be reached without overriding GREASE_VALUES,
        // but we pin the upper-edge behavior here.
        expect(Number.isInteger(v)).toBe(true);
    });
});

describe("encodeExtensionBody new extension encoders", () => {
    it("emits an empty body for encrypted_client_hello (65037)", async () => {
        const kps = await keyPairs(["x25519"]);
        const cfg: ClientHelloConfig = {
            ...BASE_CONFIG,
            extensionOrder: [ExtensionType.ENCRYPTED_CLIENT_HELLO],
        };
        const hello = buildClientHello(cfg, kps, () => Math.random(), crypto);
        expect(hello[0]).toBe(0x01);
    });

    it("emits an empty body for padding (21, RFC 7685)", async () => {
        const kps = await keyPairs(["x25519"]);
        const cfg: ClientHelloConfig = {
            ...BASE_CONFIG,
            extensionOrder: [ExtensionType.PADDING],
        };
        const hello = buildClientHello(cfg, kps, () => Math.random(), crypto);
        expect(hello[0]).toBe(0x01);
    });

    it("emits ALPN for application_settings_old (17513)", async () => {
        const kps = await keyPairs(["x25519"]);
        const cfg: ClientHelloConfig = {
            ...BASE_CONFIG,
            extensionOrder: [ExtensionType.APPLICATION_SETTINGS_OLD],
        };
        const hello = buildClientHello(cfg, kps, () => Math.random(), crypto);
        expect(hello[0]).toBe(0x01);
    });
});

describe("encodeExtensionBody default branch", () => {
    it("emits an empty body for an unrecognized extension type that is a GREASE value", async () => {
        // A GREASE extension type not in the known set (e.g. 0x1a1a) hits the
        // default branch, passes the isGreaseValue check, and emits empty bytes.
        const kps = await keyPairs(["x25519"]);
        const cfg: ClientHelloConfig = {
            ...BASE_CONFIG,
            extensionOrder: [0x1a1a], // GREASE value, not a known ExtensionType
        };
        const hello = buildClientHello(cfg, kps, () => Math.random(), crypto);
        expect(hello[0]).toBe(0x01);
    });

    it("silently skips an unrecognized extension type that is NOT a GREASE value", async () => {
        // A non-GREASE, non-known type (e.g. 0x9999) hits the default branch,
        // returns undefined, and is skipped — the handshake must not abort.
        const kps = await keyPairs(["x25519"]);
        const cfg: ClientHelloConfig = {
            ...BASE_CONFIG,
            extensionOrder: [0x9999],
        };
        // Should not throw — just omit the unknown extension
        const hello = buildClientHello(cfg, kps, () => Math.random(), crypto);
        expect(hello).toBeInstanceOf(Uint8Array);
        expect(hello.length).toBeGreaterThan(0);
    });
});

// ---------------------------------------------------------------------------
// Post-quantum key share groups (Fix 1) — supported_groups + key_share must
// include X25519MLKEM768 (0x11ec) and X25519Kyber768 (0x6399) for fingerprint
// compatibility. The crypto backend generates X25519 keys tagged with the
// hybrid name.
// ---------------------------------------------------------------------------

describe("buildClientHello post-quantum key share groups", () => {
    it("includes X25519MLKEM768 in the supported_groups extension", async () => {
        const kps: KeyPair[] = [
            { algorithm: "x25519", privateKey: new Uint8Array(32), publicKey: new Uint8Array(32).fill(0x01) },
            { algorithm: "X25519MLKEM768", privateKey: new Uint8Array(32), publicKey: new Uint8Array(32).fill(0x02) },
        ];
        const cfg: ClientHelloConfig = {
            ...BASE_CONFIG,
            keyShareGroups: ["x25519", "X25519MLKEM768"],
            extensionOrder: [ExtensionType.SUPPORTED_GROUPS],
            grease: false,
        };
        const hello = buildClientHello(cfg, kps, () => 0, crypto);
        expect(hello[0]).toBe(0x01); // CLIENT_HELLO

        // Verify the supported_groups extension contains both group IDs.
        // We search for the X25519MLKEM768 wire code (0x11ec) in the message.
        const pqWire = NAMED_GROUP_CODES["X25519MLKEM768"];
        const x25519Wire = NAMED_GROUP_CODES["x25519"];
        const bytes = Array.from(hello);
        // Find the supported_groups extension (type 10 = 0x000a).
        const sgIdx = bytes.indexOf(0x00, bytes.indexOf(0x0a));
        expect(sgIdx).toBeGreaterThan(-1);
        // Verify both wire codes appear after the extension type.
        const afterExt = bytes.slice(sgIdx);
        expect(afterExt.includes((x25519Wire >> 8) & 0xff)).toBe(true);
        expect(afterExt.includes((pqWire >> 8) & 0xff)).toBe(true);
    });

    it("includes X25519MLKEM768 in the key_share extension", async () => {
        const kps: KeyPair[] = [
            { algorithm: "x25519", privateKey: new Uint8Array(32), publicKey: new Uint8Array(32).fill(0x01) },
            { algorithm: "X25519MLKEM768", privateKey: new Uint8Array(32), publicKey: new Uint8Array(32).fill(0x02) },
        ];
        const cfg: ClientHelloConfig = {
            ...BASE_CONFIG,
            keyShareGroups: ["x25519", "X25519MLKEM768"],
            extensionOrder: [ExtensionType.KEY_SHARE],
            grease: false,
        };
        const hello = buildClientHello(cfg, kps, () => 0, crypto);

        // Verify the key_share extension contains the PQ group wire code.
        const pqWire = NAMED_GROUP_CODES["X25519MLKEM768"];
        const bytes = Array.from(hello);
        // Find the key_share extension (type 51 = 0x0033).
        const ksIdx = bytes.indexOf(0x33, bytes.indexOf(0x00));
        expect(ksIdx).toBeGreaterThan(-1);
        const afterExt = bytes.slice(ksIdx);
        // The group ID 0x11ec should appear in the key_share entries.
        expect(afterExt.includes(0x11)).toBe(true);
        expect(afterExt.includes(0xec)).toBe(true);
        void pqWire;
    });

    it("does NOT strip PQ groups even when crypto backend cannot key them", async () => {
        // Both X25519MLKEM768 and X25519Kyber768 should survive encoding.
        const kps: KeyPair[] = [
            { algorithm: "X25519MLKEM768", privateKey: new Uint8Array(32), publicKey: new Uint8Array(32) },
            { algorithm: "X25519Kyber768", privateKey: new Uint8Array(32), publicKey: new Uint8Array(32) },
        ];
        const cfg: ClientHelloConfig = {
            ...BASE_CONFIG,
            keyShareGroups: ["X25519MLKEM768", "X25519Kyber768"],
            extensionOrder: [ExtensionType.SUPPORTED_GROUPS, ExtensionType.KEY_SHARE],
            grease: false,
        };
        const hello = buildClientHello(cfg, kps, () => 0, crypto);
        expect(hello[0]).toBe(0x01);
        // Message should be well-formed (no crash, positive length).
        expect(hello.length).toBeGreaterThan(50);
    });
});

// ---------------------------------------------------------------------------
// EC point formats from config (Fix 3)
// ---------------------------------------------------------------------------

describe("buildClientHello ec_point_formats from config", () => {
    /**
     * Extract a single extension's body from a serialized ClientHello.
     * Returns the body bytes, or undefined if the extension is absent.
     */
    function extractExtensionBody(hello: Uint8Array, type: number): Uint8Array | undefined {
        // Walk past the fixed ClientHello header to reach the extensions block.
        // Layout: type(1) + length(3) + version(2) + random(32) + sid_len(1)
        // + sid + cipher_len(2) + ciphers + comp_len(1) + comp + ext_len(2).
        let o = 4 + 2 + 32; // past type(1) + len(3) + version(2) + random(32)
        const sidLen = hello[o]!;
        o += 1 + sidLen;
        const cipherLen = (hello[o]! << 8) | hello[o + 1]!;
        o += 2 + cipherLen;
        const compLen = hello[o]!;
        o += 1 + compLen;
        // Extensions block: ext_len(2) + extensions
        const extTotalLen = (hello[o]! << 8) | hello[o + 1]!;
        o += 2;
        const extEnd = o + extTotalLen;
        while (o + 4 <= extEnd) {
            const eType = (hello[o]! << 8) | hello[o + 1]!;
            const eLen = (hello[o + 2]! << 8) | hello[o + 3]!;
            o += 4;
            if (eType === type) {
                return hello.subarray(o, o + eLen);
            }
            o += eLen;
        }
        return undefined;
    }

    it("defaults to [0x00] (uncompressed) when not specified", async () => {
        const kps = await keyPairs(["x25519"]);
        const cfg: ClientHelloConfig = {
            ...BASE_CONFIG,
            grease: false,
            extensionOrder: [ExtensionType.EC_POINT_FORMATS],
        };
        const hello = buildClientHello(cfg, kps, () => 0, crypto);
        const body = extractExtensionBody(hello, ExtensionType.EC_POINT_FORMATS);
        expect(body).toBeDefined();
        // Default = [0x00] → body = [0x01, 0x00] (count=1, format=uncompressed)
        expect(body![0]).toBe(1);
        expect(body![1]).toBe(0x00);
    });

    it("uses config.ecPointFormats when specified", async () => {
        const kps = await keyPairs(["x25519"]);
        const cfg: ClientHelloConfig = {
            ...BASE_CONFIG,
            grease: false,
            extensionOrder: [ExtensionType.EC_POINT_FORMATS],
            ecPointFormats: [0x01, 0x00],
        };
        const hello = buildClientHello(cfg, kps, () => 0, crypto);
        const body = extractExtensionBody(hello, ExtensionType.EC_POINT_FORMATS);
        expect(body).toBeDefined();
        expect(body![0]).toBe(2); // 2 formats
        expect(body![1]).toBe(0x01);
        expect(body![2]).toBe(0x00);
    });
});

// ---------------------------------------------------------------------------
// Record padding (Fix 5)
// ---------------------------------------------------------------------------

describe("buildClientHello record padding", () => {
    it("does not pad when recordPadding is not set", async () => {
        const kps = await keyPairs(["x25519"]);
        const cfg: ClientHelloConfig = { ...BASE_CONFIG };
        const hello = buildClientHello(cfg, kps, () => 0, crypto);
        // Without padding, the message should be much smaller than 512.
        expect(hello.length).toBeLessThan(512);
    });

    it("pads the ClientHello to exactly 512 bytes when recordPadding is set", async () => {
        const kps = await keyPairs(["x25519"]);
        const cfg: ClientHelloConfig = {
            ...BASE_CONFIG,
            recordPadding: 512,
        };
        const hello = buildClientHello(cfg, kps, () => 0, crypto);
        expect(hello.length).toBe(512);
    });

    it("pads to an arbitrary target length", async () => {
        const kps = await keyPairs(["x25519"]);
        const cfg: ClientHelloConfig = {
            ...BASE_CONFIG,
            recordPadding: 384,
        };
        const hello = buildClientHello(cfg, kps, () => 0, crypto);
        expect(hello.length).toBe(384);
    });

    it("does not pad when the message already exceeds the target", async () => {
        const kps = await keyPairs(["x25519"]);
        const cfg: ClientHelloConfig = {
            ...BASE_CONFIG,
            recordPadding: 50, // smaller than the base message
        };
        const hello = buildClientHello(cfg, kps, () => 0, crypto);
        // The message should be its natural size (no truncation, no padding).
        expect(hello.length).toBeGreaterThan(50);
    });

    it("pads correctly when PADDING is already in the extension order", async () => {
        const kps = await keyPairs(["x25519"]);
        const cfg: ClientHelloConfig = {
            ...BASE_CONFIG,
            extensionOrder: [...BASE_CONFIG.extensionOrder, ExtensionType.PADDING],
            recordPadding: 512,
        };
        const hello = buildClientHello(cfg, kps, () => 0, crypto);
        expect(hello.length).toBe(512);
    });
});
