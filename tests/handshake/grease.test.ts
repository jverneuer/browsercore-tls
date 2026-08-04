/**
 * Tests for @browsercore/tls RFC 8701 GREASE (Generate Random Extensions And
 * Sustain Extensibility).
 *
 * Every function in src/handshake/grease.ts is exercised with deterministic
 * (seeded or fixed) random values so the assertions are stable. The goal is
 * 100% branch + line + statement coverage on the module.
 */

import { describe, it, expect } from "vitest";
import {
    GREASE_VALUES,
    generateGreaseCipherSuite,
    generateGreaseExtensionType,
    insertGrease,
    applyGreaseToClientHello,
    type Profile,
} from "../../src/handshake/grease.js";
import { ExtensionType } from "../../src/extensions/extensions.js";
import type { ClientHello } from "../../src/handshake/handshake-types.js";

/** Index 0 sentinel — what random()=0.0 always resolves to. */
const FIRST_GREASE = 0x0a0a;
/** Index 8 sentinel — what random()=0.5 resolves to (floor(0.5*16)=8). */
const MID_GREASE = 0x8a8a;
/** Index 15 sentinel — what random()=0.999 resolves to. */
const LAST_GREASE = 0xfafa;

/** Deterministic random that always returns the same value. */
const fixedRandom = (value: number) => (): number => value;

/**
 * Build a single extension record: type(2) || data_len(2) || data.
 * Mirrors the wire layout used by extensions.ts so tests stay aligned with
 * the real encoder.
 */
function ext(type: number, data: Uint8Array): Uint8Array {
    const out = new Uint8Array(2 + 2 + data.length);
    out[0] = (type >> 8) & 0xff;
    out[1] = type & 0xff;
    out[2] = (data.length >> 8) & 0xff;
    out[3] = data.length & 0xff;
    out.set(data, 4);
    return out;
}

/** Wrap a list of serialized extensions under the 2-byte block length prefix. */
function extensionsBlock(...extensions: readonly Uint8Array[]): Uint8Array {
    let total = 0;
    for (const e of extensions) {
        total += e.length;
    }
    const out = new Uint8Array(2 + total);
    out[0] = (total >> 8) & 0xff;
    out[1] = total & 0xff;
    let o = 2;
    for (const e of extensions) {
        out.set(e, o);
        o += e.length;
    }
    return out;
}

/** Build a minimal ClientHello for applyGreaseToClientHello tests. */
function makeHello(cipherSuites: readonly number[], extensions: Uint8Array): ClientHello {
    return {
        protocolVersion: 0x0303,
        random: new Uint8Array(32),
        sessionId: new Uint8Array(0),
        cipherSuites: [...cipherSuites],
        compressionMethods: [0x00],
        extensions,
    };
}

describe("GREASE_VALUES", () => {
    it("contains exactly the 16 RFC 8701 §2 sentinels", () => {
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
});

describe("generateGreaseCipherSuite", () => {
    it("returns the sentinel at index 0 when random()=0.0", () => {
        expect(generateGreaseCipherSuite(fixedRandom(0.0))).toBe(FIRST_GREASE);
    });

    it("returns the sentinel at index 8 when random()=0.5", () => {
        expect(generateGreaseCipherSuite(fixedRandom(0.5))).toBe(MID_GREASE);
    });

    it("returns the sentinel at index 15 when random()≈1.0", () => {
        expect(generateGreaseCipherSuite(fixedRandom(0.999))).toBe(LAST_GREASE);
    });

    it("always returns a value from the GREASE set (default random)", () => {
        for (let i = 0; i < 50; i++) {
            expect(GREASE_VALUES).toContain(generateGreaseCipherSuite());
        }
    });
});

describe("generateGreaseExtensionType", () => {
    it("returns the sentinel at index 0 when random()=0.0", () => {
        expect(generateGreaseExtensionType(fixedRandom(0.0))).toBe(FIRST_GREASE);
    });

    it("returns the sentinel at index 15 when random()≈1.0", () => {
        expect(generateGreaseExtensionType(fixedRandom(0.999))).toBe(LAST_GREASE);
    });

    it("always returns a value from the GREASE set (default random)", () => {
        for (let i = 0; i < 50; i++) {
            expect(GREASE_VALUES).toContain(generateGreaseExtensionType());
        }
    });
});

describe("insertGrease", () => {
    it("prepends a GREASE value to an empty list", () => {
        const out = insertGrease([], fixedRandom(0.0));
        expect(out).toEqual([FIRST_GREASE]);
    });

    it("prepends a GREASE value to a non-empty list", () => {
        const out = insertGrease([0x1301, 0x1302], fixedRandom(0.0));
        expect(out).toEqual([FIRST_GREASE, 0x1301, 0x1302]);
    });

    it("does not mutate the input array", () => {
        const input = [0x1301];
        const out = insertGrease(input, fixedRandom(0.0));
        expect(input).toEqual([0x1301]); // unchanged
        expect(out).not.toBe(input); // new reference
        expect(out).toEqual([FIRST_GREASE, 0x1301]);
    });

    it("avoids duplicating a GREASE value already present", () => {
        // random()=0.0 would pick 0x0a0a, but it is excluded, so the next
        // sentinel in filter order (0x1a1a) is chosen.
        const out = insertGrease([FIRST_GREASE], fixedRandom(0.0));
        expect(out[0]).not.toBe(FIRST_GREASE);
        expect(GREASE_VALUES).toContain(out[0]);
        expect(out).toHaveLength(2);
    });

    it("throws when every sentinel is already present (degenerate)", () => {
        // All 16 GREASE values in the input → nothing left to pick.
        expect(() => insertGrease([...GREASE_VALUES], fixedRandom(0.0))).toThrow(
            /unreachable|empty/i,
        );
    });
});

describe("applyGreaseToClientHello", () => {
    it("returns the same reference when profile.grease is false (Firefox)", () => {
        const hello = makeHello([0x1301], new Uint8Array(0));
        const profile: Profile = { grease: false };
        const out = applyGreaseToClientHello(hello, profile, fixedRandom(0.0));
        // Identity check — Firefox must not be touched.
        expect(out).toBe(hello);
    });

    it("prepends a GREASE cipher suite when grease is true", () => {
        const hello = makeHello([0x1301, 0x1302], new Uint8Array(0));
        const profile: Profile = { grease: true };
        const out = applyGreaseToClientHello(hello, profile, fixedRandom(0.0));
        expect(out).not.toBe(hello); // new object
        expect(out.cipherSuites[0]).toBe(FIRST_GREASE);
        expect(out.cipherSuites.slice(1)).toEqual([0x1301, 0x1302]);
    });

    it("does not mutate the input hello", () => {
        const hello = makeHello([0x1301], new Uint8Array(0));
        const original = { ...hello, cipherSuites: [...hello.cipherSuites] };
        applyGreaseToClientHello(hello, { grease: true }, fixedRandom(0.0));
        expect(hello.cipherSuites).toEqual(original.cipherSuites);
    });

    it("preserves non-cipher/extension fields verbatim", () => {
        const hello = makeHello([0x1301], new Uint8Array(0));
        hello.random[0] = 0x42;
        const out = applyGreaseToClientHello(hello, { grease: true }, fixedRandom(0.0));
        expect(out.protocolVersion).toBe(hello.protocolVersion);
        expect(out.random).toBe(hello.random); // same reference
        expect(out.sessionId).toBe(hello.sessionId);
        expect(out.compressionMethods).toBe(hello.compressionMethods);
    });

    it("handles an empty extensions block (no extensions to grease)", () => {
        // Empty extensions → parseExtensionsRaw returns [], then only the
        // trailing GREASE extension types are appended.
        const hello = makeHello([0x1301], new Uint8Array(0));
        const out = applyGreaseToClientHello(hello, { grease: true }, fixedRandom(0.0));
        // extensions block: length(2)=4 (one GREASE ext type: 2+2+0 bytes).
        expect(out.extensions.length).toBe(2 + 4);
        expect(out.extensions[0]).toBe(0x00);
        expect(out.extensions[1]).toBe(0x04); // block length = 4 bytes
    });

    it("injects a GREASE version into supported_versions", () => {
        // supported_versions client body: len(1) || versions*(2). TLS 1.3 = 0x0304.
        const svBody = new Uint8Array([0x02, 0x03, 0x04]);
        const svExt = ext(ExtensionType.SUPPORTED_VERSIONS, svBody);
        const hello = makeHello([0x1301], extensionsBlock(svExt));
        const out = applyGreaseToClientHello(hello, { grease: true }, fixedRandom(0.0));

        // Parse the greased extensions block and find supported_versions.
        const blockLen = (out.extensions[0]! << 8) | out.extensions[1]!;
        let o = 2;
        let found: Uint8Array | undefined;
        while (o < 2 + blockLen) {
            const type = (out.extensions[o]! << 8) | out.extensions[o + 1]!;
            const len = (out.extensions[o + 2]! << 8) | out.extensions[o + 3]!;
            if (type === ExtensionType.SUPPORTED_VERSIONS) {
                found = out.extensions.subarray(o + 4, o + 4 + len);
            }
            o += 4 + len;
        }
        expect(found).toBeDefined();
        // New body: len(1)=4 || 0x0a0a || 0x0304.
        expect(found![0]).toBe(0x04); // length byte
        expect((found![1]! << 8) | found![2]!).toBe(FIRST_GREASE);
        expect((found![3]! << 8) | found![4]!).toBe(0x0304);
    });

    it("injects a GREASE group into supported_groups", () => {
        // supported_groups body: len(2) || groups*(2). x25519 = 0x001d.
        const sgBody = new Uint8Array([0x00, 0x02, 0x00, 0x1d]);
        const sgExt = ext(ExtensionType.SUPPORTED_GROUPS, sgBody);
        const hello = makeHello([0x1301], extensionsBlock(sgExt));
        const out = applyGreaseToClientHello(hello, { grease: true }, fixedRandom(0.0));

        const blockLen = (out.extensions[0]! << 8) | out.extensions[1]!;
        let o = 2;
        let found: Uint8Array | undefined;
        while (o < 2 + blockLen) {
            const type = (out.extensions[o]! << 8) | out.extensions[o + 1]!;
            const len = (out.extensions[o + 2]! << 8) | out.extensions[o + 3]!;
            if (type === ExtensionType.SUPPORTED_GROUPS) {
                found = out.extensions.subarray(o + 4, o + 4 + len);
            }
            o += 4 + len;
        }
        expect(found).toBeDefined();
        // New body: len(2)=0x0004 || 0x0a0a || 0x001d.
        expect(((found![0]! << 8) | found![1]!)).toBe(0x0004);
        expect((found![2]! << 8) | found![3]!).toBe(FIRST_GREASE);
        expect((found![4]! << 8) | found![5]!).toBe(0x001d);
    });

    it("injects a GREASE key share entry", () => {
        // key_share client body: len(2) || entries*(group(2)+len(2)+key).
        // One x25519 entry with a 1-byte dummy key.
        const ksBody = new Uint8Array([0x00, 0x05, 0x00, 0x1d, 0x00, 0x01, 0x42]);
        const ksExt = ext(ExtensionType.KEY_SHARE, ksBody);
        const hello = makeHello([0x1301], extensionsBlock(ksExt));
        const out = applyGreaseToClientHello(hello, { grease: true }, fixedRandom(0.0));

        const blockLen = (out.extensions[0]! << 8) | out.extensions[1]!;
        let o = 2;
        let found: Uint8Array | undefined;
        while (o < 2 + blockLen) {
            const type = (out.extensions[o]! << 8) | out.extensions[o + 1]!;
            const len = (out.extensions[o + 2]! << 8) | out.extensions[o + 3]!;
            if (type === ExtensionType.KEY_SHARE) {
                found = out.extensions.subarray(o + 4, o + 4 + len);
            }
            o += 4 + len;
        }
        expect(found).toBeDefined();
        // New body: len(2) || [GREASE entry: group(2)+len(2)+0] || old entry.
        // Old entry was 5 bytes; new GREASE entry is 4 bytes (empty key).
        // Length field = 4 + 5 = 9 = 0x0009.
        expect(((found![0]! << 8) | found![1]!)).toBe(0x0009);
        // GREASE entry at offset 2: group=0x0a0a, keylen=0x0000.
        expect((found![2]! << 8) | found![3]!).toBe(FIRST_GREASE);
        expect((found![4]! << 8) | found![5]!).toBe(0x0000);
        // Old x25519 entry follows at offset 6.
        expect((found![6]! << 8) | found![7]!).toBe(0x001d);
    });

    it("appends a GREASE extension type to the block", () => {
        // Start with one real extension (supported_versions). After greasing,
        // the block contains supported_versions + 1 GREASE extension.
        const svBody = new Uint8Array([0x02, 0x03, 0x04]);
        const svExt = ext(ExtensionType.SUPPORTED_VERSIONS, svBody);
        const hello = makeHello([0x1301], extensionsBlock(svExt));
        const out = applyGreaseToClientHello(hello, { grease: true }, fixedRandom(0.0));

        // The last extension in the block should be a GREASE type.
        // Parse backwards: find the last extension.
        const blockLen = (out.extensions[0]! << 8) | out.extensions[1]!;
        let o = 2;
        let lastType = -1;
        while (o < 2 + blockLen) {
            const type = (out.extensions[o]! << 8) | out.extensions[o + 1]!;
            const len = (out.extensions[o + 2]! << 8) | out.extensions[o + 3]!;
            lastType = type;
            o += 4 + len;
        }
        expect(GREASE_VALUES).toContain(lastType);
    });

    it("uses distinct GREASE values across cipher suites and extensions", () => {
        // With random()=0.0, cipher suite gets FIRST_GREASE (0x0a0a). The
        // supported_versions GREASE is also 0x0a0a (no collision), but the
        // trailing GREASE extension must avoid both. Verify uniqueness.
        const svBody = new Uint8Array([0x02, 0x03, 0x04]);
        const svExt = ext(ExtensionType.SUPPORTED_VERSIONS, svBody);
        const hello = makeHello([0x1301], extensionsBlock(svExt));
        const out = applyGreaseToClientHello(hello, { grease: true }, fixedRandom(0.0));

        // Collect all GREASE values present in the output.
        const seen = new Set<number>();
        // Cipher suite GREASE.
        expect(GREASE_VALUES).toContain(out.cipherSuites[0]);
        seen.add(out.cipherSuites[0]!);
        // Walk extensions, record GREASE types and GREASE data.
        const blockLen = (out.extensions[0]! << 8) | out.extensions[1]!;
        let o = 2;
        while (o < 2 + blockLen) {
            const type = (out.extensions[o]! << 8) | out.extensions[o + 1]!;
            const len = (out.extensions[o + 2]! << 8) | out.extensions[o + 3]!;
            if (GREASE_VALUES.includes(type)) {
                // Trailing GREASE extension — type must be unique.
                expect(seen.has(type)).toBe(false);
                seen.add(type);
            }
            o += 4 + len;
        }
    });

    it("stops at valid prefix when a trailing extension header is incomplete", () => {
        // Block declares two bytes of body (totalLen=2) but the single
        // extension header needs 4 bytes. The `offset + 4 > end` guard breaks
        // cleanly without throwing.
        const shortBlock = new Uint8Array([0x00, 0x02, 0x00, 0x0a, 0x00]);
        // end = 2 + 2 = 4; offset starts at 2; offset+4=6 > 4 → break.
        const hello = makeHello([0x1301], shortBlock);
        const out = applyGreaseToClientHello(hello, { grease: true }, fixedRandom(0.0));
        expect(out.cipherSuites[0]).toBe(FIRST_GREASE);
    });

    it("stops when an extension's declared data length exceeds the block", () => {
        // One extension claims dataLen=8 but only 2 bytes of body remain.
        // The `dataEnd > end` guard breaks cleanly.
        const block = new Uint8Array([0x00, 0x06, 0x00, 0x0a, 0x00, 0x08, 0x01, 0x02]);
        // end = 2 + 6 = 8; ext at offset 2: type=10, dataLen=8; dataEnd=2+4+8=14 > 8 → break.
        const hello = makeHello([0x1301], block);
        const out = applyGreaseToClientHello(hello, { grease: true }, fixedRandom(0.0));
        expect(out.cipherSuites[0]).toBe(FIRST_GREASE);
    });

    it("handles empty body in prependToVersionList (defensive branch)", () => {
        // supported_versions with a zero-length body.
        const svExt = ext(ExtensionType.SUPPORTED_VERSIONS, new Uint8Array(0));
        const hello = makeHello([0x1301], extensionsBlock(svExt));
        const out = applyGreaseToClientHello(hello, { grease: true }, fixedRandom(0.0));
        expect(out.cipherSuites[0]).toBe(FIRST_GREASE);
        // The greased supported_versions body should be: len(1)=2 || 0x0a0a.
        const blockLen = (out.extensions[0]! << 8) | out.extensions[1]!;
        let o = 2;
        let found: Uint8Array | undefined;
        while (o < 2 + blockLen) {
            const type = (out.extensions[o]! << 8) | out.extensions[o + 1]!;
            const len = (out.extensions[o + 2]! << 8) | out.extensions[o + 3]!;
            if (type === ExtensionType.SUPPORTED_VERSIONS) {
                found = out.extensions.subarray(o + 4, o + 4 + len);
            }
            o += 4 + len;
        }
        expect(found).toBeDefined();
        expect(found![0]).toBe(0x02); // length byte
        expect((found![1]! << 8) | found![2]!).toBe(FIRST_GREASE);
    });

    it("handles empty body in prependToGroupList (defensive branch)", () => {
        const sgExt = ext(ExtensionType.SUPPORTED_GROUPS, new Uint8Array(0));
        const hello = makeHello([0x1301], extensionsBlock(sgExt));
        const out = applyGreaseToClientHello(hello, { grease: true }, fixedRandom(0.0));
        const blockLen = (out.extensions[0]! << 8) | out.extensions[1]!;
        let o = 2;
        let found: Uint8Array | undefined;
        while (o < 2 + blockLen) {
            const type = (out.extensions[o]! << 8) | out.extensions[o + 1]!;
            const len = (out.extensions[o + 2]! << 8) | out.extensions[o + 3]!;
            if (type === ExtensionType.SUPPORTED_GROUPS) {
                found = out.extensions.subarray(o + 4, o + 4 + len);
            }
            o += 4 + len;
        }
        expect(found).toBeDefined();
        // New body: len(2)=0x0002 || 0x0a0a.
        expect(((found![0]! << 8) | found![1]!)).toBe(0x0002);
        expect((found![2]! << 8) | found![3]!).toBe(FIRST_GREASE);
    });

    it("handles empty body in prependKeyShare (defensive branch)", () => {
        const ksExt = ext(ExtensionType.KEY_SHARE, new Uint8Array(0));
        const hello = makeHello([0x1301], extensionsBlock(ksExt));
        const out = applyGreaseToClientHello(hello, { grease: true }, fixedRandom(0.0));
        const blockLen = (out.extensions[0]! << 8) | out.extensions[1]!;
        let o = 2;
        let found: Uint8Array | undefined;
        while (o < 2 + blockLen) {
            const type = (out.extensions[o]! << 8) | out.extensions[o + 1]!;
            const len = (out.extensions[o + 2]! << 8) | out.extensions[o + 3]!;
            if (type === ExtensionType.KEY_SHARE) {
                found = out.extensions.subarray(o + 4, o + 4 + len);
            }
            o += 4 + len;
        }
        expect(found).toBeDefined();
        // New body: len(2)=0x0004 || [GREASE group + keylen=0].
        expect(((found![0]! << 8) | found![1]!)).toBe(0x0004);
        expect((found![2]! << 8) | found![3]!).toBe(FIRST_GREASE);
    });

    it("passes through unknown extension types unmodified (default branch)", () => {
        // Signature algorithms (type 13) is not GREASE-sentitive in our impl.
        const saBody = new Uint8Array([0x00, 0x02, 0x04, 0x03]);
        const saExt = ext(ExtensionType.SIGNATURE_ALGORITHMS, saBody);
        const hello = makeHello([0x1301], extensionsBlock(saExt));
        const out = applyGreaseToClientHello(hello, { grease: true }, fixedRandom(0.0));
        const blockLen = (out.extensions[0]! << 8) | out.extensions[1]!;
        let o = 2;
        let found: Uint8Array | undefined;
        while (o < 2 + blockLen) {
            const type = (out.extensions[o]! << 8) | out.extensions[o + 1]!;
            const len = (out.extensions[o + 2]! << 8) | out.extensions[o + 3]!;
            if (type === ExtensionType.SIGNATURE_ALGORITHMS) {
                found = out.extensions.subarray(o + 4, o + 4 + len);
            }
            o += 4 + len;
        }
        expect(found).toBeDefined();
        // Unchanged body.
        expect(found).toEqual(saBody);
    });

    it("throws when extensions block is truncated mid-header (readByte branch)", () => {
        // Declared block length says 4 bytes follow, but only 2 are present.
        // parseExtensionsRaw must detect the truncation and throw.
        const truncated = new Uint8Array([0x00, 0x04, 0x00, 0x2b]);
        const hello = makeHello([0x1301], truncated);
        expect(() => applyGreaseToClientHello(hello, { grease: true }, fixedRandom(0.0))).toThrow(
            /truncated/,
        );
    });
});
