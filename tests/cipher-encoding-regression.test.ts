/**
 * Regression tests for cipher-suite wire encoding (@browsercore/tls).
 *
 * Pins the correct behavior of cipherSuiteToWire():
 *   1. It must THROW on an unknown suite — never silently encode it as
 *      0x0000. Before the fix, unknown suites hit the default branch and
 *      returned undefined, which the caller packed into the wire as 0x0000,
 *      producing a malformed ClientHello that servers reject with decode_error.
 *   2. Every known CipherSuite member maps to its correct, non-zero IANA wire
 *      value, and the mapping is injective (no two suites collide).
 *   3. The GREASE placeholder (TLS_GREASE_RESERVED_0) maps to the canonical
 *      0x0a0a sentinel — the value real Chrome uses to GREASE cipher suites.
 *
 * These tests are exhaustive over the CipherSuite union, so extending the
 * union without updating the encoder causes a compile error (assertNever) and
 * is caught here as a runtime throw.
 */

import { describe, it, expect } from "vitest";
import { cipherSuiteToWire } from "../src/handshake/client-hello.js";
import type { CipherSuite } from "../src/types.js";

/**
 * The authoritative IANA mapping for every CipherSuite the shipped browser
 * profiles offer. Mirrors the switch in cipherSuiteToWire() — kept here as the
 * source of truth the regression asserts against.
 */
const EXPECTED_WIRE: Readonly<Record<CipherSuite, number>> = {
    // GREASE sentinel (RFC 8701).
    "TLS_GREASE_RESERVED_0": 0x0a0a,
    // TLS 1.3 AEAD suites.
    "TLS_AES_128_GCM_SHA256": 0x1301,
    "TLS_AES_256_GCM_SHA384": 0x1302,
    "TLS_CHACHA20_POLY1305_SHA256": 0x1303,
    "TLS_AES_128_CCM_SHA256": 0x1304,
    // TLS 1.2 ECDHE/GCM suites.
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256": 0xc02b,
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256": 0xc02f,
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384": 0xc02c,
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384": 0xc030,
    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256": 0xcca9,
    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256": 0xcca8,
    // TLS 1.2 ECDHE/CBC suites.
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA": 0xc013,
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA": 0xc014,
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA": 0xc009,
    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA": 0xc00a,
    // TLS 1.2 RSA suites.
    "TLS_RSA_WITH_AES_128_GCM_SHA256": 0x009c,
    "TLS_RSA_WITH_AES_256_GCM_SHA384": 0x009d,
    "TLS_RSA_WITH_AES_128_CBC_SHA": 0x002f,
    "TLS_RSA_WITH_AES_256_CBC_SHA": 0x0035,
};

/** Every member of the CipherSuite union, in declaration order. */
const ALL_SUITES: readonly CipherSuite[] = Object.keys(EXPECTED_WIRE) as readonly CipherSuite[];

describe("cipherSuiteToWire must throw on unknown suites (never silently encode 0x0000)", () => {
    it("throws when given a suite not in the CipherSuite union", () => {
        // Pre-fix: unknown suites fell through to a default that returned
        // undefined → packed into the wire as 0x0000. The fix routes unknowns
        // to assertNever, which throws. Cast bypasses the type system to
        // simulate a buggy caller / corrupted profile data.
        const bogus = "TLS_FAKE_SUITE_DOES_NOT_EXIST" as unknown as CipherSuite;
        expect(() => cipherSuiteToWire(bogus)).toThrow();
    });

    it("does NOT return 0x0000 for any known suite", () => {
        // Direct invariant: no known suite may ever encode to the null IANA code.
        for (const suite of ALL_SUITES) {
            expect(cipherSuiteToWire(suite)).not.toBe(0x0000);
        }
    });
});

describe("cipherSuiteToWire maps every known suite to its correct IANA wire value", () => {
    it("matches the authoritative IANA mapping for every CipherSuite member", () => {
        for (const suite of ALL_SUITES) {
            const wire = cipherSuiteToWire(suite);
            expect(wire).toBe(EXPECTED_WIRE[suite]);
        }
    });

    it("produces a valid 16-bit value for every suite", () => {
        for (const suite of ALL_SUITES) {
            const wire = cipherSuiteToWire(suite);
            expect(wire).toBeGreaterThan(0);
            expect(wire).toBeLessThanOrEqual(0xffff);
        }
    });

    it("is injective — no two distinct suites collide to the same wire value", () => {
        const seen = new Map<number, CipherSuite>();
        for (const suite of ALL_SUITES) {
            const wire = cipherSuiteToWire(suite);
            const clash = seen.get(wire);
            expect(clash).toBeUndefined();
            seen.set(wire, suite);
        }
        // Sanity: the mapping covers all 19 members of the union.
        expect(seen.size).toBe(ALL_SUITES.length);
    });
});

describe("GREASE placeholder encodes to the canonical 0x0a0a sentinel", () => {
    it("maps TLS_GREASE_RESERVED_0 to 0x0a0a", () => {
        expect(cipherSuiteToWire("TLS_GREASE_RESERVED_0")).toBe(0x0a0a);
    });

    it("encodes GREASE to a value matching the RFC 8701 0x?a?a pattern", () => {
        const wire = cipherSuiteToWire("TLS_GREASE_RESERVED_0");
        const hi = (wire >> 8) & 0xff;
        const lo = wire & 0xff;
        expect(hi).toBe(lo);
        expect(lo & 0x0f).toBe(0x0a);
    });
});
