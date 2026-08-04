/**
 * Exhaustiveness test: every cipher suite name advertised by a shipped browser
 * profile is wire-encodable by the tls layer.
 *
 * This is the single most important invariant for the cipher-suite system: if a
 * profile offers a suite that tls can't encode, the ClientHello build hits
 * `assertNever` and crashes. By importing the real profile definitions from
 * @browsercore/profiles and asserting each offered suite passes `isCipherSuite`
 * and maps to a non-zero wire code, we guarantee the tls-side table stays in
 * sync with the profiles-side data.
 */

import { describe, it, expect } from "vitest";
import {
    ALL_CIPHER_SUITES,
    cipherSuiteToWire,
    isCipherSuite,
} from "../src/handshake/client-hello.js";
import {
    ChromeProfiles,
    FirefoxProfiles,
    SafariProfiles,
    EdgeProfiles,
} from "@browsercore/profiles";

const PROFILE_MAP = {
    ...ChromeProfiles,
    ...FirefoxProfiles,
    ...SafariProfiles,
    ...EdgeProfiles,
} as const;

describe("every profile cipher suite is wire-encodable", () => {
    for (const [key, profile] of Object.entries(PROFILE_MAP)) {
        describe(`${key} (${profile.name} ${profile.version})`, () => {
            for (const cs of profile.tls.cipherSuites) {
                it(`${cs} is a known CipherSuite`, () => {
                    expect(isCipherSuite(cs)).toBe(true);
                });

                it(`${cs} maps to a non-zero wire code`, () => {
                    // isCipherSuite(cs) is true, so the cast is sound.
                    const wire = cipherSuiteToWire(cs as (typeof ALL_CIPHER_SUITES)[number]);
                    expect(wire).toBeGreaterThan(0);
                    expect(wire).toBeLessThanOrEqual(0xffff);
                });
            }
        });
    }
});

describe("ALL_CIPHER_SUITES covers every profile suite", () => {
    const allProfileSuites = new Set<string>();
    for (const profile of Object.values(PROFILE_MAP)) {
        for (const cs of profile.tls.cipherSuites) {
            allProfileSuites.add(cs);
        }
    }

    it("includes every suite used by any profile", () => {
        for (const cs of allProfileSuites) {
            expect(ALL_CIPHER_SUITES).toContain(cs);
        }
    });

    it("contains no entries that are not wire-encodable", () => {
        for (const cs of ALL_CIPHER_SUITES) {
            const wire = cipherSuiteToWire(cs);
            expect(wire).toBeGreaterThan(0);
            expect(wire).toBeLessThanOrEqual(0xffff);
        }
    });
});
