/**
 * Targeted coverage for the uncovered branches in crypto/keySchedule.ts.
 *
 * The two largest gaps are the TLS 1.2 / GREASE cipher-suite branches in
 * cipherSuiteToHash and cipherSuiteKeyLength — every legacy suite is mapped
 * to `throwKeyScheduleError`, but no existing test exercises those cases. The
 * HKDF-Expand-Label SHA-384 hash branch is also untested, and the SHA-384
 * suite path through the secret-derivation helpers is missing.
 */

import { describe, it, expect } from "vitest";
import { crypto, SHA_256, SHA_384 } from "@browsercore/crypto";
import {
    cipherSuiteToHash,
    cipherSuiteKeyLength,
    deriveHandshakeSecrets,
    hkdfExpandLabel,
} from "../src/crypto/keySchedule.js";
import { TlsKeyScheduleError } from "../src/errors.js";
import type { CipherSuite } from "../src/types.js";

/**
 * The cipher suites that this client can OFFER (GREASE + TLS 1.2) but never
 * NEGOTIATE — they are not valid TLS 1.3 AEAD suites, so both cipherSuiteToHash
 * and cipherSuiteKeyLength throw TlsKeyScheduleError for each of them.
 */
const LEGACY_SUITES: readonly CipherSuite[] = [
    "TLS_GREASE_RESERVED_0",
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
    "TLS_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_RSA_WITH_AES_128_CBC_SHA",
    "TLS_RSA_WITH_AES_256_CBC_SHA",
];

describe("cipherSuiteToHash — legacy suites throw TlsKeyScheduleError", () => {
    it("rejects every non-negotiable cipher suite", () => {
        for (const suite of LEGACY_SUITES) {
            try {
                cipherSuiteToHash(suite);
                expect.unreachable(`expected TlsKeyScheduleError for ${suite}`);
            } catch (e) {
                expect(e).toBeInstanceOf(TlsKeyScheduleError);
                // All suites share the "has no HKDF hash mapping" message.
                expect((e as Error).message).toMatch(/no HKDF hash mapping/u);
            }
        }
    });

    it("hits the assertNever default for an unrecognised CipherSuite", () => {
        // The switch is exhaustive over CipherSuite; a runtime value outside the
        // union drives the default branch.
        const bogus = "TLS_FUTURE_SUITE" as unknown as CipherSuite;
        expect(() => cipherSuiteToHash(bogus)).toThrow(/Unexpected value/u);
    });
});

describe("cipherSuiteKeyLength — legacy suites throw TlsKeyScheduleError", () => {
    it("rejects every non-negotiable cipher suite", () => {
        for (const suite of LEGACY_SUITES) {
            try {
                cipherSuiteKeyLength(suite);
                expect.unreachable(`expected TlsKeyScheduleError for ${suite}`);
            } catch (e) {
                expect(e).toBeInstanceOf(TlsKeyScheduleError);
                expect((e as Error).message).toMatch(/no AEAD key length/u);
            }
        }
    });

    it("hits the assertNever default for an unrecognised CipherSuite", () => {
        const bogus = "TLS_FUTURE_SUITE" as unknown as CipherSuite;
        expect(() => cipherSuiteKeyLength(bogus)).toThrow(/Unexpected value/u);
    });
});

describe("hkdfExpandLabel — SHA-384 hash branch", () => {
    it("uses SHA-384 when asked", () => {
        const secret = crypto.randomBytes(48);
        // SHA-384 hashLen = 48; requesting 48 bytes exercises a single-block
        // HKDF-Expand with the SHA-384 code path.
        const out = hkdfExpandLabel(secret, "key", new Uint8Array(0), 48, SHA_384);
        expect(out.length).toBe(48);
    });

    it("produces a different result for SHA-384 vs SHA-256 at the same length", () => {
        const secret = crypto.randomBytes(48);
        const out384 = hkdfExpandLabel(secret, "key", new Uint8Array(0), 48, SHA_384);
        const out256 = hkdfExpandLabel(secret, "key", new Uint8Array(0), 48, SHA_256);
        expect(out384).not.toEqual(out256);
    });
});

describe("deriveHandshakeSecrets — SHA-384 path through the derivation pipeline", () => {
    it("returns a 48-byte master secret for TLS_AES_256_GCM_SHA384", () => {
        const sharedSecret = crypto.randomBytes(32);
        // SHA-384 hash length is 48 — derive the transcript with sha384.
        const helloTranscript = crypto.sha384(new Uint8Array([0x01, 0x02]));
        const { masterSecret, traffic } = deriveHandshakeSecrets(
            sharedSecret,
            helloTranscript,
            "TLS_AES_256_GCM_SHA384",
        );
        expect(masterSecret.length).toBe(48);
        expect(traffic.client.key.length).toBe(32);
        expect(traffic.server.key.length).toBe(32);
    });

    it("uses SHA-256 for the ChaCha20 suite (SHA-256 hash branch in the pipeline)", () => {
        const sharedSecret = crypto.randomBytes(32);
        const helloTranscript = crypto.sha256(new Uint8Array([0x03]));
        const { masterSecret } = deriveHandshakeSecrets(
            sharedSecret,
            helloTranscript,
            "TLS_CHACHA20_POLY1305_SHA256",
        );
        expect(masterSecret.length).toBe(32);
    });

    it("uses SHA-256 for the AES-128-CCM suite", () => {
        const sharedSecret = crypto.randomBytes(32);
        const helloTranscript = crypto.sha256(new Uint8Array([0x04]));
        const { masterSecret } = deriveHandshakeSecrets(
            sharedSecret,
            helloTranscript,
            "TLS_AES_128_CCM_SHA256",
        );
        expect(masterSecret.length).toBe(32);
    });
});
