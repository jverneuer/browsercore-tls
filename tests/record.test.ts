/**
 * Tests for @browsercore/tls record layer (RFC 8446 §5).
 *
 * encryptRecord / decryptRecord are pure AEAD steps that delegate to
 * @browsercore/crypto. We exercise every supported AEAD algorithm plus the
 * exhaustiveness guard (default -> assertNever) by feeding an algorithm the
 * type system would reject but that is a valid runtime string.
 */

import { describe, it, expect } from "vitest";
import { createTestCryptoProvider } from "./test-helpers.js";
import type { CryptoProvider } from "@browsercore/contracts";
import {
    encryptRecord,
    decryptRecord,
    cipherSuiteToAead,
    serializeRecordHeader,
} from "../src/record/record.js";
import { TlsDecryptError } from "../src/errors.js";
import type { AeadAlgorithm, CipherSuite } from "../src/types.js";

/**
 * node:crypto-backed provider for record-layer round-trip tests. The
 * defensive-cause test below builds a separate provider whose decrypt
 * primitive throws a non-Error value.
 */
const crypto = createTestCryptoProvider();

/** Key + nonce sizes per AEAD algorithm (bytes). */
function keyNonceFor(algorithm: AeadAlgorithm): { key: Uint8Array; nonce: Uint8Array } {
    switch (algorithm) {
        case "AES-128-GCM":
            return { key: crypto.randomBytes(16), nonce: crypto.randomBytes(12) };
        case "AES-256-GCM":
            return { key: crypto.randomBytes(32), nonce: crypto.randomBytes(12) };
        case "AES-128-CCM":
            return { key: crypto.randomBytes(16), nonce: crypto.randomBytes(12) };
        case "CHACHA20-POLY1305":
            return { key: crypto.randomBytes(32), nonce: crypto.randomBytes(12) };
    }
}

describe("cipherSuiteToAead", () => {
    it("maps every cipher suite to its AEAD algorithm", () => {
        const cases: ReadonlyArray<[CipherSuite, AeadAlgorithm]> = [
            ["TLS_AES_128_GCM_SHA256", "AES-128-GCM"],
            ["TLS_AES_256_GCM_SHA384", "AES-256-GCM"],
            ["TLS_CHACHA20_POLY1305_SHA256", "CHACHA20-POLY1305"],
        ];
        for (const [suite, expected] of cases) {
            expect(cipherSuiteToAead(suite)).toBe(expected);
        }
    });

    it("maps the AES-128-CCM suite to its AEAD algorithm like the other TLS 1.3 suites", () => {
        // AES-128-CCM is now backed by @browsercore/crypto (aes-128-ccm), so it maps
        // to "AES-128-CCM" alongside the GCM and ChaCha20-Poly1305 suites.
        expect(cipherSuiteToAead("TLS_AES_128_CCM_SHA256")).toBe("AES-128-CCM");
    });
});

describe("encryptRecord / decryptRecord round-trip", () => {
    it("round-trips AES-128-GCM", () => {
        const { key, nonce } = keyNonceFor("AES-128-GCM");
        const plaintext = new TextEncoder().encode("hello aes-128-gcm");
        const aad = serializeRecordHeader(23, plaintext.length + 16);
        const ciphertext = encryptRecord(plaintext, key, nonce, aad, "AES-128-GCM", crypto);
        expect(ciphertext.length).toBe(plaintext.length + 16); // + tag
        const recovered = decryptRecord(ciphertext, key, nonce, aad, "AES-128-GCM", crypto);
        expect(recovered).toEqual(plaintext);
    });

    it("round-trips AES-256-GCM", () => {
        const { key, nonce } = keyNonceFor("AES-256-GCM");
        const plaintext = new TextEncoder().encode("hello aes-256-gcm");
        const aad = serializeRecordHeader(23, plaintext.length + 16);
        const ciphertext = encryptRecord(plaintext, key, nonce, aad, "AES-256-GCM", crypto);
        const recovered = decryptRecord(ciphertext, key, nonce, aad, "AES-256-GCM", crypto);
        expect(recovered).toEqual(plaintext);
    });

    it("round-trips ChaCha20-Poly1305", () => {
        const { key, nonce } = keyNonceFor("CHACHA20-POLY1305");
        const plaintext = new TextEncoder().encode("hello chacha20-poly1305");
        const aad = serializeRecordHeader(23, plaintext.length + 16);
        const ciphertext = encryptRecord(plaintext, key, nonce, aad, "CHACHA20-POLY1305", crypto);
        const recovered = decryptRecord(ciphertext, key, nonce, aad, "CHACHA20-POLY1305", crypto);
        expect(recovered).toEqual(plaintext);
    });

    it("round-trips AES-128-CCM", () => {
        const { key, nonce } = keyNonceFor("AES-128-CCM");
        const plaintext = new TextEncoder().encode("hello aes-128-ccm");
        const aad = serializeRecordHeader(23, plaintext.length + 16);
        const ciphertext = encryptRecord(plaintext, key, nonce, aad, "AES-128-CCM", crypto);
        expect(ciphertext.length).toBe(plaintext.length + 16); // + tag
        const recovered = decryptRecord(ciphertext, key, nonce, aad, "AES-128-CCM", crypto);
        expect(recovered).toEqual(plaintext);
    });

    it("decryption fails with TlsDecryptError when the authentication tag is wrong", () => {
        const { key, nonce } = keyNonceFor("AES-128-GCM");
        const plaintext = new TextEncoder().encode("integrity matters");
        const aad = serializeRecordHeader(23, plaintext.length + 16);
        const ciphertext = encryptRecord(plaintext, key, nonce, aad, "AES-128-GCM", crypto);
        // Corrupt the last byte (part of the authentication tag).
        ciphertext[ciphertext.length - 1] ^= 0xff;
        expect(() => decryptRecord(ciphertext, key, nonce, aad, "AES-128-GCM", crypto)).toThrow(TlsDecryptError);
    });

    it("decryption fails with TlsDecryptError when the AAD does not match", () => {
        const { key, nonce } = keyNonceFor("AES-128-GCM");
        const plaintext = new TextEncoder().encode("aad binds the header");
        const aad = serializeRecordHeader(23, plaintext.length + 16);
        const ciphertext = encryptRecord(plaintext, key, nonce, aad, "AES-128-GCM", crypto);
        // A different header -> different AAD -> auth failure.
        const otherAad = serializeRecordHeader(22, plaintext.length + 16);
        expect(() => decryptRecord(ciphertext, key, nonce, otherAad, "AES-128-GCM", crypto)).toThrow(TlsDecryptError);
    });
});

describe("decryptRecord defensive cause handling", () => {
    it("wraps a non-Error throw from the AEAD primitive as TlsDecryptError (no cause)", async () => {
        // The catch branch at line 177 handles the case where the AEAD primitive
        // throws something that is NOT an Error instance. The real
        // @browsercore/crypto always throws DecryptError, so we simulate a
        // misbehaving backend with a provider whose decrypt throws a bare string.
        const key = crypto.randomBytes(16);
        const nonce = crypto.randomBytes(12);
        const aad = serializeRecordHeader(22, 16);
        const badProvider: CryptoProvider = {
            ...crypto,
            aes128GcmDecrypt: () => {
                throw "corrupt"; // non-Error throw
            },
        };
        expect(() => decryptRecord(new Uint8Array(16), key, nonce, aad, "AES-128-GCM", badProvider)).toThrow(
            TlsDecryptError,
        );
    });
});

describe("exhaustiveness guards (default -> assertNever)", () => {
    it("encryptRecord hits the default branch for an unrecognized algorithm", () => {
        const { key, nonce } = keyNonceFor("AES-128-GCM");
        const plaintext = new TextEncoder().encode("x");
        const aad = serializeRecordHeader(23, plaintext.length + 16);
        // "AES-128-OCB" is not a valid AeadAlgorithm (not in the union), but at
        // runtime the switch only sees a string — this exercises the
        // exhaustiveness default.
        const bad = "AES-128-OCB" as unknown as AeadAlgorithm;
        expect(() => encryptRecord(plaintext, key, nonce, aad, bad, crypto)).toThrow(/Unexpected value/);
    });

    it("decryptRecord hits the default branch for an unrecognized algorithm", () => {
        const { key, nonce } = keyNonceFor("AES-128-GCM");
        const plaintext = new TextEncoder().encode("x");
        const aad = serializeRecordHeader(23, plaintext.length + 16);
        const ciphertext = encryptRecord(plaintext, key, nonce, aad, "AES-128-GCM", crypto);
        const bad = "AES-128-OCB" as unknown as AeadAlgorithm;
        // The default throws inside the try; the catch wraps it as TlsDecryptError.
        expect(() => decryptRecord(ciphertext, key, nonce, aad, bad, crypto)).toThrow(TlsDecryptError);
    });
});
