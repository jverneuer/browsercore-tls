/**
 * Regression tests for GREASE generation in ClientHello (@browsercore/tls).
 *
 * Pins the correct behavior when profile.grease = true (Chrome/Edge/Safari):
 *   6. Every ClientHello contains a GREASE cipher suite — prepended to the
 *      offered list per RFC 8701, matching real-browser behavior.
 *   7. Every ClientHello contains a GREASE extension — a 0x?a?a extension type
 *      with empty body, prepended ahead of the profile's extension order.
 *   8. Every ClientHello contains a GREASE key share — a 0x?a?a key-share group
 *      entry prepended to the key_share extension.
 *
 * When grease = false (Firefox), none of these appear.
 *
 * The canonical GREASE sentinel this implementation emits is 0x0a0a (the first
 * RFC 8701 value); tests assert both the exact sentinel and the structural
 * 0x?a?a pattern so the intent is pinned even if the sentinel choice changes.
 */

import { describe, it, expect } from "vitest";
import { createTestCryptoProvider } from "./test-helpers.js";

const crypto = createTestCryptoProvider();
import { buildClientHello } from "../src/handshake/client-hello.js";
import { ExtensionType } from "../src/extensions/extensions.js";
import { TLS_1_2, TLS_1_3 } from "../src/types.js";
import type { ClientHelloConfig, KeyPair } from "../src/types.js";

/** RFC 8701 §2: every GREASE value has identical bytes with low nibble 0xA. */
function isGreasePattern(value: number): boolean {
    if (value <= 0 || value > 0xffff) {
        return false;
    }
    const hi = (value >> 8) & 0xff;
    const lo = value & 0xff;
    return hi === lo && (lo & 0x0f) === 0x0a;
}

/** Canonical GREASE sentinel emitted by this implementation's ClientHello. */
const CANONICAL_GREASE = 0x0a0a;

async function x25519KeyPair(): Promise<readonly KeyPair[]> {
    const kp = crypto.x25519GenerateKeyPair();
    return [{ algorithm: "x25519", privateKey: kp.secretKey, publicKey: kp.publicKey }];
}

/** Parse the offered cipher suites from a serialized ClientHello. */
function parseCipherSuites(hello: Uint8Array): readonly number[] {
    let o = 4 + 2 + 32; // handshake header + version + random
    const sidLen = hello[o] ?? 0;
    o += 1 + sidLen;
    const csLen = ((hello[o] ?? 0) << 8) | (hello[o + 1] ?? 0);
    o += 2;
    const suites: number[] = [];
    for (let i = 0; i < csLen; i += 2) {
        suites.push(((hello[o + i] ?? 0) << 8) | (hello[o + i + 1] ?? 0));
    }
    return suites;
}

/** Parse the extensions block into ordered { type, data } records. */
function parseExtensions(hello: Uint8Array): ReadonlyArray<{ type: number; data: Uint8Array }> {
    let o = 4 + 2 + 32;
    o += 1 + (hello[o] ?? 0); // session id
    o += 2 + (((hello[o] ?? 0) << 8) | (hello[o + 1] ?? 0)); // cipher suites
    o += 1 + (hello[o] ?? 0); // compression
    const extLen = ((hello[o] ?? 0) << 8) | (hello[o + 1] ?? 0);
    o += 2;
    const end = o + extLen;
    const out: { type: number; data: Uint8Array }[] = [];
    while (o < end) {
        const type = ((hello[o] ?? 0) << 8) | (hello[o + 1] ?? 0);
        const dataLen = ((hello[o + 2] ?? 0) << 8) | (hello[o + 3] ?? 0);
        out.push({ type, data: hello.subarray(o + 4, o + 4 + dataLen) });
        o += 4 + dataLen;
    }
    return out;
}

/** A chrome-style config (grease=true) with a realistic cipher + extension set. */
function greasedConfig(): ClientHelloConfig {
    return {
        cipherSuites: [
            "TLS_AES_128_GCM_SHA256",
            "TLS_AES_256_GCM_SHA384",
            "TLS_CHACHA20_POLY1305_SHA256",
        ],
        extensionOrder: [
            ExtensionType.SERVER_NAME, // 0
            ExtensionType.SUPPORTED_GROUPS, // 10
            ExtensionType.SIGNATURE_ALGORITHMS, // 13
            ExtensionType.SUPPORTED_VERSIONS, // 43
            ExtensionType.KEY_SHARE, // 51
        ],
        keyShareGroups: ["x25519", "secp256r1"],
        signatureAlgorithms: ["ecdsa_secp256r1_sha256"],
        supportedVersions: [TLS_1_3],
        serverName: "example.com",
        alpnProtocols: ["h2"],
        grease: true,
    };
}

describe("Every ClientHello (grease=true) contains GREASE in cipher suites", () => {
    it("prepends a GREASE cipher suite (0x0a0a) at the front of the offered list", async () => {
        // Pin the per-connection sentinel deterministically (random()=0.0 -> 0x0a0a).
        const hello = buildClientHello(greasedConfig(), await x25519KeyPair(), () => 0.0, crypto);
        const suites = parseCipherSuites(hello);
        expect(suites.length).toBeGreaterThan(0);
        expect(suites[0]).toBe(CANONICAL_GREASE);
    });

    it("prepends a GREASE value matching the RFC 8701 0x?a?a pattern", async () => {
        const hello = buildClientHello(greasedConfig(), await x25519KeyPair(), () => Math.random(), crypto);
        const suites = parseCipherSuites(hello);
        expect(isGreasePattern(suites[0]!)).toBe(true);
    });

    it("places GREASE first even when the profile omits TLS_GREASE_RESERVED_0", async () => {
        // The profile here does NOT list TLS_GREASE_RESERVED_0 — yet the encoder
        // must still prepend the canonical GREASE sentinel when grease=true.
        const hello = buildClientHello(greasedConfig(), await x25519KeyPair(), () => 0.0, crypto);
        const suites = parseCipherSuites(hello);
        expect(suites[0]).toBe(CANONICAL_GREASE);
        // The real ciphers follow the GREASE sentinel.
        expect(suites.slice(1)).toEqual([0x1301, 0x1302, 0x1303]);
    });

    it("prepends GREASE to an otherwise single-suite list", async () => {
        const cfg: ClientHelloConfig = {
            ...greasedConfig(),
            cipherSuites: ["TLS_AES_128_GCM_SHA256"],
        };
        const hello = buildClientHello(cfg, await x25519KeyPair(), () => 0.0, crypto);
        const suites = parseCipherSuites(hello);
        expect(suites[0]).toBe(CANONICAL_GREASE);
        expect(suites).toHaveLength(2); // GREASE + the single real suite
    });
});

describe("Every ClientHello (grease=true) contains a GREASE extension", () => {
    it("prepends a GREASE extension (type 0x0a0a) ahead of the profile order", async () => {
        const hello = buildClientHello(greasedConfig(), await x25519KeyPair(), () => 0.0, crypto);
        const extensions = parseExtensions(hello);
        expect(extensions.length).toBeGreaterThan(0);
        expect(extensions[0]!.type).toBe(CANONICAL_GREASE);
    });

    it("the GREASE extension type matches the RFC 8701 0x?a?a pattern", async () => {
        const hello = buildClientHello(greasedConfig(), await x25519KeyPair(), () => Math.random(), crypto);
        const extensions = parseExtensions(hello);
        expect(isGreasePattern(extensions[0]!.type)).toBe(true);
    });

    it("the GREASE extension body is empty (GREASE has no payload)", async () => {
        const hello = buildClientHello(greasedConfig(), await x25519KeyPair(), () => Math.random(), crypto);
        const extensions = parseExtensions(hello);
        expect(extensions[0]!.data.length).toBe(0);
    });

    it("the profile's extensions follow the GREASE extension in order", async () => {
        const hello = buildClientHello(greasedConfig(), await x25519KeyPair(), () => 0.0, crypto);
        const extensions = parseExtensions(hello);
        const types = extensions.map((e) => e.type);
        expect(types[0]).toBe(CANONICAL_GREASE);
        // A trailing GREASE sentinel (RFC 8701) terminates the list with the
        // same per-connection value as the leading one.
        expect(types[types.length - 1]).toBe(CANONICAL_GREASE);
        expect(types.slice(1, -1)).toEqual([0, 10, 13, 43, 51]);
    });
});

describe("Every ClientHello (grease=true) contains a GREASE key share", () => {
    it("prepends a GREASE key-share group (0x0a0a) in the key_share extension", async () => {
        const hello = buildClientHello(greasedConfig(), await x25519KeyPair(), () => 0.0, crypto);
        const extensions = parseExtensions(hello);
        const ks = extensions.find((e) => e.type === ExtensionType.KEY_SHARE);
        expect(ks).toBeDefined();
        // key_share body: client_shares_len(2) || share { group(2), key_len(2), key }.
        const firstGroup = ((ks!.data[2] ?? 0) << 8) | (ks!.data[3] ?? 0);
        expect(firstGroup).toBe(CANONICAL_GREASE);
    });

    it("the GREASE key-share group matches the RFC 8701 0x?a?a pattern", async () => {
        const hello = buildClientHello(greasedConfig(), await x25519KeyPair(), () => Math.random(), crypto);
        const extensions = parseExtensions(hello);
        const ks = extensions.find((e) => e.type === ExtensionType.KEY_SHARE);
        const firstGroup = ((ks!.data[2] ?? 0) << 8) | (ks!.data[3] ?? 0);
        expect(isGreasePattern(firstGroup)).toBe(true);
    });

    it("the real key-share groups follow the GREASE group", async () => {
        const hello = buildClientHello(greasedConfig(), await x25519KeyPair(), () => 0.0, crypto);
        const extensions = parseExtensions(hello);
        const ks = extensions.find((e) => e.type === ExtensionType.KEY_SHARE)!;
        // GREASE group at offset 2, real group right after (GREASE key is 32 bytes).
        const greaseGroup = ((ks.data[2] ?? 0) << 8) | (ks.data[3] ?? 0);
        const greaseKeyLen = ((ks.data[4] ?? 0) << 8) | (ks.data[5] ?? 0);
        expect(greaseGroup).toBe(CANONICAL_GREASE);
        expect(greaseKeyLen).toBe(32);
        // First real group follows the GREASE entry (2+2+32 bytes later).
        const firstRealGroup = ((ks.data[2 + 2 + 2 + 32] ?? 0) << 8) | (ks.data[2 + 2 + 2 + 32 + 1] ?? 0);
        expect(firstRealGroup).toBe(0x001d); // x25519
    });
});

describe("No GREASE is generated when grease=false (Firefox-style)", () => {
    function firefoxConfig(): ClientHelloConfig {
        return { ...greasedConfig(), grease: false };
    }

    it("does not prepend a GREASE cipher suite", async () => {
        const hello = buildClientHello(firefoxConfig(), await x25519KeyPair(), () => Math.random(), crypto);
        const suites = parseCipherSuites(hello);
        expect(suites[0]).not.toBe(CANONICAL_GREASE);
        expect(isGreasePattern(suites[0]!)).toBe(false);
        expect(suites).toEqual([0x1301, 0x1302, 0x1303]);
    });

    it("does not prepend a GREASE extension", async () => {
        const hello = buildClientHello(firefoxConfig(), await x25519KeyPair(), () => Math.random(), crypto);
        const extensions = parseExtensions(hello);
        expect(extensions[0]!.type).not.toBe(CANONICAL_GREASE);
        expect(isGreasePattern(extensions[0]!.type)).toBe(false);
        expect(extensions.map((e) => e.type)).toEqual([0, 10, 13, 43, 51]);
    });

    it("does not prepend a GREASE key-share group", async () => {
        const hello = buildClientHello(firefoxConfig(), await x25519KeyPair(), () => Math.random(), crypto);
        const extensions = parseExtensions(hello);
        const ks = extensions.find((e) => e.type === ExtensionType.KEY_SHARE)!;
        const firstGroup = ((ks.data[2] ?? 0) << 8) | (ks.data[3] ?? 0);
        expect(firstGroup).not.toBe(CANONICAL_GREASE);
        expect(isGreasePattern(firstGroup)).toBe(false);
        expect(firstGroup).toBe(0x001d); // x25519, the first real group
    });
});

// ---------------------------------------------------------------------------
// Trailing GREASE extension (RFC 8701) — Chrome parity.
// Real browsers terminate the extension list with a GREASE value that reuses
// the same per-connection sentinel as the leading GREASE.
// ---------------------------------------------------------------------------

describe("Trailing GREASE extension (grease=true)", () => {
    it("appends a GREASE extension as the absolute last extension", async () => {
        const hello = buildClientHello(greasedConfig(), await x25519KeyPair(), () => 0.0, crypto);
        const extensions = parseExtensions(hello);
        const last = extensions[extensions.length - 1];
        expect(last).toBeDefined();
        expect(isGreasePattern(last!.type)).toBe(true);
        // Reuses the same per-connection sentinel as the leading GREASE.
        expect(last!.type).toBe(CANONICAL_GREASE);
        expect(last!.type).toBe(extensions[0]!.type);
    });

    it("the trailing GREASE extension body is empty", async () => {
        const hello = buildClientHello(greasedConfig(), await x25519KeyPair(), () => Math.random(), crypto);
        const extensions = parseExtensions(hello);
        const last = extensions[extensions.length - 1]!;
        expect(last.data.length).toBe(0);
    });

    it("reuses the same sentinel for leading and trailing GREASE", async () => {
        // random()=0.5 -> MID_GREASE (0x8a8a) in both leading and trailing slots.
        const hello = buildClientHello(greasedConfig(), await x25519KeyPair(), () => 0.5, crypto);
        const extensions = parseExtensions(hello);
        expect(extensions[0]!.type).toBe(0x8a8a);
        expect(extensions[extensions.length - 1]!.type).toBe(0x8a8a);
    });

    it("does NOT append a trailing GREASE extension when grease=false", async () => {
        const hello = buildClientHello({ ...greasedConfig(), grease: false }, await x25519KeyPair(), () => Math.random(), crypto);
        const extensions = parseExtensions(hello);
        const last = extensions[extensions.length - 1]!;
        expect(isGreasePattern(last.type)).toBe(false);
        // The last extension is key_share (51), not a GREASE value.
        expect(last.type).toBe(ExtensionType.KEY_SHARE);
    });
});

// ---------------------------------------------------------------------------
// supported_versions: [GREASE, TLS 1.3, TLS 1.2] — Chrome parity.
// Chrome advertises a leading GREASE version and always appends TLS 1.2 for
// middlebox compatibility, even though the handshake negotiates TLS 1.3.
// ---------------------------------------------------------------------------

describe("supported_versions advertises GREASE + TLS 1.2 (grease=true)", () => {
    it("encodes [GREASE(0x0a0a), TLS 1.3(0x0304), TLS 1.2(0x0303)]", async () => {
        const hello = buildClientHello(greasedConfig(), await x25519KeyPair(), () => 0.0, crypto);
        const extensions = parseExtensions(hello);
        const sv = extensions.find((e) => e.type === ExtensionType.SUPPORTED_VERSIONS);
        expect(sv).toBeDefined();
        // Body: 1-byte length (6) || GREASE || TLS 1.3 || TLS 1.2.
        expect(Array.from(sv!.data)).toEqual([0x06, 0x0a, 0x0a, 0x03, 0x04, 0x03, 0x03]);
    });

    it("the leading GREASE version reuses the per-connection sentinel", async () => {
        // random()=0.5 -> MID_GREASE (0x8a8a).
        const hello = buildClientHello(greasedConfig(), await x25519KeyPair(), () => 0.5, crypto);
        const extensions = parseExtensions(hello);
        const sv = extensions.find((e) => e.type === ExtensionType.SUPPORTED_VERSIONS)!;
        const firstVersion = ((sv.data[1] ?? 0) << 8) | (sv.data[2] ?? 0);
        expect(firstVersion).toBe(0x8a8a);
    });
});

describe("supported_versions advertises TLS 1.2 even when grease=false", () => {
    it("encodes [TLS 1.3(0x0304), TLS 1.2(0x0303)] with no GREASE", async () => {
        const hello = buildClientHello({ ...greasedConfig(), grease: false }, await x25519KeyPair(), () => Math.random(), crypto);
        const extensions = parseExtensions(hello);
        const sv = extensions.find((e) => e.type === ExtensionType.SUPPORTED_VERSIONS);
        expect(sv).toBeDefined();
        // Body: 1-byte length (4) || TLS 1.3 || TLS 1.2. No GREASE version.
        expect(Array.from(sv!.data)).toEqual([0x04, 0x03, 0x04, 0x03, 0x03]);
    });

    it("does not duplicate TLS 1.2 when the profile already lists it", async () => {
        // A profile that already advertises TLS 1.2 must not get a second copy
        // appended — the dedup guard (`!allVersions.includes(0x0303)`) fires.
        const cfg: ClientHelloConfig = { ...greasedConfig(), grease: false, supportedVersions: [TLS_1_3, TLS_1_2] };
        const hello = buildClientHello(cfg, await x25519KeyPair(), () => Math.random(), crypto);
        const extensions = parseExtensions(hello);
        const sv = extensions.find((e) => e.type === ExtensionType.SUPPORTED_VERSIONS);
        expect(sv).toBeDefined();
        // Exactly one TLS 1.3 and one TLS 1.2 — no duplication.
        expect(Array.from(sv!.data)).toEqual([0x04, 0x03, 0x04, 0x03, 0x03]);
    });
});
