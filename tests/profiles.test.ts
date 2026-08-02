/**
 * Tests for @browsercore/tls ClientHello configuration profiles.
 *
 * profiles.ts is a pure registry: named TlsProfile records, a lookup, and a
 * resolver that fills in the connection-specific serverName. No crypto, no IO.
 */

import { describe, it, expect } from "vitest";
import {
    MODERN_TLS13_PROFILE,
    COMPATIBILITY_PROFILE,
    PROFILES,
    getProfile,
    resolveProfile,
} from "../src/profiles/profiles.js";

describe("profiles registry", () => {
    it("exposes the modern-tls13 profile with TLS 1.3 only", () => {
        expect(MODERN_TLS13_PROFILE.name).toBe("modern-tls13");
        expect(MODERN_TLS13_PROFILE.config.supportedVersions).toEqual([{ name: "TLS 1.3", wire: 0x0304 }]);
        // X25519 + secp256r1 key shares, modern ciphers.
        expect(MODERN_TLS13_PROFILE.config.keyShareGroups).toContain("x25519");
        expect(MODERN_TLS13_PROFILE.config.cipherSuites).toContain("TLS_AES_128_GCM_SHA256");
    });

    it("exposes the compatibility profile with a TLS 1.2 fallback", () => {
        expect(COMPATIBILITY_PROFILE.name).toBe("compatibility");
        const wires = COMPATIBILITY_PROFILE.config.supportedVersions.map((v) => v.wire);
        expect(wires).toContain(0x0304); // TLS 1.3
        expect(wires).toContain(0x0303); // TLS 1.2
    });

    it("registers every profile by name", () => {
        expect(Object.keys(PROFILES).sort()).toEqual(["compatibility", "modern-tls13"]);
        expect(PROFILES["modern-tls13"]).toBe(MODERN_TLS13_PROFILE);
        expect(PROFILES["compatibility"]).toBe(COMPATIBILITY_PROFILE);
    });
});

describe("getProfile", () => {
    it("returns the profile for a known name", () => {
        expect(getProfile("modern-tls13")).toBe(MODERN_TLS13_PROFILE);
        expect(getProfile("compatibility")).toBe(COMPATIBILITY_PROFILE);
    });

    it("returns undefined for an unknown name", () => {
        expect(getProfile("does-not-exist")).toBeUndefined();
    });
});

describe("resolveProfile", () => {
    it("fills in the serverName onto a copy of the profile config", () => {
        const config = resolveProfile("modern-tls13", "example.com");
        expect(config.serverName).toBe("example.com");
        // The rest of the config is preserved.
        expect(config.cipherSuites).toEqual(MODERN_TLS13_PROFILE.config.cipherSuites);
        expect(config.supportedVersions).toEqual(MODERN_TLS13_PROFILE.config.supportedVersions);
    });

    it("throws for an unknown profile name", () => {
        expect(() => resolveProfile("nope", "example.com")).toThrow(/unknown TLS profile/);
    });
});
