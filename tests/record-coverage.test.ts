/**
 * Targeted coverage for the uncovered branches in record.ts.
 *
 * - cipherSuiteToAead() with TLS 1.2 suites (throws NotImplementedError)
 * - cipherSuiteToAead() with an unknown suite (hits the assertNever default)
 * - parseRecordHeader() with a truncated buffer (throws TlsDecryptError)
 * - decryptRecord() with a provider that throws a non-Error value
 */

import { describe, it, expect } from "vitest";
import { createTestCryptoProvider } from "./test-helpers.js";
import type { CryptoProvider } from "@browsercore/contracts";

const crypto = createTestCryptoProvider();
import {
    cipherSuiteToAead,
    decryptRecord,
    parseRecordHeader,
    serializeRecordHeader,
} from "../src/record/record.js";
import { NotImplementedError, TlsDecryptError } from "../src/errors.js";
import type { AeadAlgorithm, CipherSuite } from "../src/types.js";

describe("cipherSuiteToAead — TLS 1.2 suites throw NotImplementedError", () => {
    it("throws for TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", () => {
        expect(() => cipherSuiteToAead("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")).toThrow(NotImplementedError);
    });

    it("throws for TLS_RSA_WITH_AES_256_CBC_SHA", () => {
        expect(() => cipherSuiteToAead("TLS_RSA_WITH_AES_256_CBC_SHA")).toThrow(NotImplementedError);
    });

    it("throws for the GREASE placeholder", () => {
        expect(() => cipherSuiteToAead("TLS_GREASE_RESERVED_0")).toThrow(NotImplementedError);
    });
});

describe("cipherSuiteToAead — assertNever default for unknown suite", () => {
    it("hits the default branch for an unrecognized cipher suite string", () => {
        // "UNKNOWN_SUITE" is not a valid CipherSuite, but at runtime the switch
        // only sees a string — this exercises the exhaustiveness default.
        const bad = "UNKNOWN_SUITE" as unknown as CipherSuite;
        expect(() => cipherSuiteToAead(bad)).toThrow(/Unexpected value/);
    });
});

describe("parseRecordHeader — truncated buffer", () => {
    it("throws TlsDecryptError when the buffer is shorter than 5 bytes", () => {
        const short = new Uint8Array(3);
        expect(() => parseRecordHeader(short)).toThrow(TlsDecryptError);
    });

    it("throws TlsDecryptError for an empty buffer", () => {
        expect(() => parseRecordHeader(new Uint8Array(0))).toThrow(TlsDecryptError);
    });
});

describe("decryptRecord — non-Error throw from provider", () => {
    it("wraps a non-Error throw from the AEAD primitive as TlsDecryptError (no cause)", () => {
        const key = crypto.randomBytes(16);
        const nonce = crypto.randomBytes(12);
        const aad = serializeRecordHeader(22, 16);
        // A provider whose decrypt primitive throws a bare string (not an Error).
        // The catch branch at record.ts:244-250 wraps it as TlsDecryptError without
        // attaching a cause, since the thrown value is not an Error instance.
        const provider = {
            aes128GcmDecrypt: () => {
                throw "corrupt"; // non-Error throw
            },
        } as unknown as CryptoProvider;
        expect(() =>
            decryptRecord(new Uint8Array(16), key, nonce, aad, "AES-128-GCM", provider),
        ).toThrow(TlsDecryptError);
    });
});
