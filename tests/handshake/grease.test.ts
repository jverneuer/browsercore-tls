/**
 * Tests for @browsercore/tls RFC 8701 GREASE (Generate Random Extensions And
 * Sustain Extensibility) — per-connection randomization.
 *
 * The old src/handshake/grease.ts module (per-slot independent values, struct
 * layer) is superseded: GREASE randomization now lives in client-hello.ts, where
 * a single random value is generated per buildClientHello call and threaded
 * through the cipher suite, extension type, and key-share group. These tests
 * cover the new GREASE_VALUES / generateGreaseValue / isGreaseValue API and
 * the defining Chrome invariant -- one value, reused across all slots.
 */

import { describe, it, expect } from "vitest";
import { crypto } from "@browsercore/crypto";
import {
    GREASE_VALUES,
    generateGreaseValue,
    isGreaseValue,
    buildClientHello,
} from "../../src/handshake/client-hello.js";
import { ExtensionType } from "../../src/extensions/extensions.js";
import { TLS_1_3 } from "../../src/types.js";
import type { ClientHelloConfig, KeyPair } from "../../src/types.js";

/** Deterministic random that always returns the same value. */
const fixedRandom = (value: number) => (): number => value;

/** Index 0 sentinel -- what random()=0.0 always resolves to (floor(0*16)=0). */
const FIRST_GREASE = 0x0a0a;
/** Index 8 sentinel -- what random()=0.5 resolves to (floor(0.5*16)=8). */
const MID_GREASE = 0x8a8a;
/** Index 15 sentinel -- what random()=0.999 resolves to (floor(0.999*16)=15). */
const LAST_GREASE = 0xfafa;

function chrome140Config(): ClientHelloConfig {
    return {
        cipherSuites: [
            "TLS_GREASE_RESERVED_0",
            "TLS_AES_128_GCM_SHA256",
            "TLS_AES_256_GCM_SHA384",
            "TLS_CHACHA20_POLY1305_SHA256",
        ],
        extensionOrder: [
            0, 10, 11, 13, 16, 17613, 18, 23, 27, 35, 41, 43, 45, 5, 51, 65281,
        ],
        keyShareGroups: ["x25519", "secp256r1"],
        signatureAlgorithms: ["ecdsa_secp256r1_sha256"],
        supportedVersions: [TLS_1_3],
        serverName: "example.com",
        alpnProtocols: ["h2", "http/1.1"],
        grease: true,
    };
}

async function makeKeyPairs(): Promise<readonly KeyPair[]> {
    const kp = crypto.x25519GenerateKeyPair();
    return [
        { algorithm: "x25519", privateKey: kp.secretKey, publicKey: kp.publicKey },
    ];
}

/** Walk a serialized ClientHello to its length-prefixed extensions block. */
function extractExtensionsBlock(hello: Uint8Array): Uint8Array {
    let o = 4; // handshake header: type(1) + length(3)
    o += 2 + 32; // legacy_version(2) + random(32)
    const sidLen = hello[o]!;
    o += 1 + sidLen;
    const csLen = (hello[o]! << 8) | hello[o + 1]!;
    o += 2 + csLen;
    const compLen = hello[o]!;
    o += 1 + compLen;
    const extStart = o;
    const extLen = (hello[o]! << 8) | hello[o + 1]!;
    return hello.subarray(extStart, extStart + 2 + extLen);
}

/** Parse the extensions block into { type, data } records (with 2-byte prefix). */
function parseExtensions(buf: Uint8Array): ReadonlyArray<{ type: number; data: Uint8Array }> {
    let o = 0;
    const total = (buf[o++]! << 8) | buf[o++]!;
    const end = o + total;
    const out: { type: number; data: Uint8Array }[] = [];
    while (o < end) {
        const type = (buf[o++]! << 8) | buf[o++]!;
        const dataLen = (buf[o++]! << 8) | buf[o++]!;
        out.push({ type, data: buf.subarray(o, o + dataLen) });
        o += dataLen;
    }
    return out;
}

/** Read the first cipher-suite wire (uint16) from a serialized ClientHello. */
function firstCipherWire(hello: Uint8Array): number {
    let o = 4; // handshake header: type(1) + length(3)
    o += 2 + 32; // legacy_version(2) + random(32)
    o += 1 + hello[o]!; // session_id_len(1) + session_id
    o += 2; // cipher_suites_len(2)
    return (hello[o]! << 8) | hello[o + 1]!;
}

/** Read the first extension type (uint16) from a serialized ClientHello. */
function firstExtensionType(hello: Uint8Array): number {
    const extBlock = extractExtensionsBlock(hello);
    return parseExtensions(extBlock)[0]!.type;
}

/** Read the first key-share group (uint16) from a serialized ClientHello. */
function firstKeyShareGroup(hello: Uint8Array): number {
    const extBlock = extractExtensionsBlock(hello);
    const extensions = parseExtensions(extBlock);
    const ks = extensions.find((e) => e.type === ExtensionType.KEY_SHARE);
    if (ks === undefined) {
        throw new Error("key_share extension not found");
    }
    // key_share body: client_shares_len(2) || share { group(2), len(2), key }.
    const data = ks.data;
    return (data[2]! << 8) | data[3]!;
}

describe("GREASE_VALUES", () => {
    it("is the canonical 16-element RFC 8701 section 2 set", () => {
        expect(GREASE_VALUES).toHaveLength(16);
        // Each sentinel has identical bytes and low nibble 0xA.
        for (const v of GREASE_VALUES) {
            const hi = (v >> 8) & 0xff;
            const lo = v & 0xff;
            expect(hi).toBe(lo);
            expect(lo & 0x0f).toBe(0x0a);
        }
        // First and last spot-check.
        expect(GREASE_VALUES[0]).toBe(0x0a0a);
        expect(GREASE_VALUES[15]).toBe(0xfafa);
    });

    it("is frozen (immutable)", () => {
        expect(Object.isFrozen(GREASE_VALUES)).toBe(true);
    });

    it("has every element satisfy the 0x?a?a predicate", () => {
        for (const v of GREASE_VALUES) {
            expect(isGreaseValue(v)).toBe(true);
        }
    });

    it("matches the exact IANA-reserved sentinels in order", () => {
        expect([...GREASE_VALUES]).toEqual([
            0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a,
            0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
            0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
            0xcaca, 0xdada, 0xeaea, 0xfafa,
        ]);
    });
});

describe("isGreaseValue", () => {
    it("accepts all 16 canonical GREASE sentinels", () => {
        for (const v of GREASE_VALUES) {
            expect(isGreaseValue(v)).toBe(true);
        }
    });

    it("rejects non-GREASE values", () => {
        expect(isGreaseValue(0x0000)).toBe(false);
        expect(isGreaseValue(0x1301)).toBe(false); // TLS_AES_128_GCM_SHA256
        expect(isGreaseValue(0x0a0b)).toBe(false); // low nibble not 0xA
        expect(isGreaseValue(0x0a0c)).toBe(false); // low nibble not 0xA
        expect(isGreaseValue(0x0b0a)).toBe(false); // high !== low
        expect(isGreaseValue(0xffff)).toBe(false); // low nibble not 0xA
    });
});

describe("generateGreaseValue", () => {
    it("returns the sentinel at index 0 when random()=0.0", () => {
        expect(generateGreaseValue(fixedRandom(0.0))).toBe(FIRST_GREASE);
    });

    it("returns the sentinel at index 8 when random()=0.5", () => {
        expect(generateGreaseValue(fixedRandom(0.5))).toBe(MID_GREASE);
    });

    it("returns the sentinel at index 15 when random() approximately 1.0", () => {
        expect(generateGreaseValue(fixedRandom(0.999))).toBe(LAST_GREASE);
    });

    it("always returns a value from GREASE_VALUES (default crypto random)", () => {
        for (let i = 0; i < 100; i++) {
            expect(GREASE_VALUES).toContain(generateGreaseValue(Math.random));
        }
    });

    it("always returns a value from GREASE_VALUES (injectable random)", () => {
        for (let i = 0; i < 100; i++) {
            expect(GREASE_VALUES).toContain(generateGreaseValue(fixedRandom(0.37)));
        }
    });
});

describe("GREASE variation across connections (RFC 8701)", () => {
    it("100 independent draws do not collapse to a single value", async () => {
        const config = chrome140Config();
        const kps = await makeKeyPairs();
        const seen = new Set<number>();
        for (let i = 0; i < 100; i++) {
            const hello = buildClientHello(config, kps, () => Math.random(), crypto);
            const first = firstCipherWire(hello);
            expect(GREASE_VALUES).toContain(first);
            seen.add(first);
        }
        // 100 independent draws from 16 values must not collapse to one value.
        expect(seen.size).toBeGreaterThan(1);
    });
});

describe("GREASE reuses one value across cipher, extension, and key-share", () => {
    it("cipher, extension, and key-share all use the same GREASE value", async () => {
        const config = chrome140Config();
        const kps = await makeKeyPairs();
        // Pin the sentinel deterministically (random()=0.0 -> 0x0a0a).
        const hello = buildClientHello(config, kps, fixedRandom(0.0), crypto);

        const cipher = firstCipherWire(hello);
        const ext = firstExtensionType(hello);
        const ks = firstKeyShareGroup(hello);

        expect(cipher).toBe(FIRST_GREASE);
        expect(ext).toBe(FIRST_GREASE);
        expect(ks).toBe(FIRST_GREASE);
        expect(cipher).toBe(ext);
        expect(ext).toBe(ks);
    });

    it("varying random produces a single consistent value within one hello", async () => {
        const config = chrome140Config();
        const kps = await makeKeyPairs();
        // random()=0.5 -> MID_GREASE (0x8a8a) in every slot.
        const hello = buildClientHello(config, kps, fixedRandom(0.5), crypto);

        expect(firstCipherWire(hello)).toBe(MID_GREASE);
        expect(firstExtensionType(hello)).toBe(MID_GREASE);
        expect(firstKeyShareGroup(hello)).toBe(MID_GREASE);
    });

    it("emits no GREASE sentinel when grease is false", async () => {
        const config: ClientHelloConfig = {
            cipherSuites: ["TLS_AES_128_GCM_SHA256"],
            extensionOrder: [0, 43, 51],
            keyShareGroups: ["x25519"],
            signatureAlgorithms: ["ecdsa_secp256r1_sha256"],
            supportedVersions: [TLS_1_3],
            serverName: "example.com",
            grease: false,
        };
        const kps = await makeKeyPairs();
        const hello = buildClientHello(config, kps, () => Math.random(), crypto);

        // First cipher is the real suite, not a GREASE sentinel.
        const cipher = firstCipherWire(hello);
        expect(isGreaseValue(cipher)).toBe(false);

        // First extension is SNI (type 0), not GREASE.
        expect(firstExtensionType(hello)).toBe(ExtensionType.SERVER_NAME);

        // First key-share group is x25519 (0x001d), not GREASE.
        const ks = firstKeyShareGroup(hello);
        expect(isGreaseValue(ks)).toBe(false);
    });
});
