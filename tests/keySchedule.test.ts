/**
 * Tests for @browsercore/tls TLS 1.3 key schedule (RFC 8446 §7.1).
 *
 * Covers the schedule helpers that tls.test.ts does not: deriveHandshakeSecrets,
 * updateTrafficSecrets, the validation asserts, the cipher-suite size mappings,
 * the SHA-384 hash case, and the HKDF-Expand length-overflow guard.
 */

import { describe, it, expect } from "vitest";
import { createTestCryptoProvider } from "./test-helpers.js";

const crypto = createTestCryptoProvider();
import {
    cipherSuiteToHash,
    cipherSuiteKeyLength,
    cipherSuiteIvLength,
    hkdfExpandLabel,
    deriveTrafficSecrets,
    deriveHandshakeSecrets,
    deriveApplicationSecrets,
    updateTrafficSecrets,
    assertCipherSuiteOffered,
    assertVersionSupported,
} from "../src/crypto/keySchedule.js";
import { TlsHandshakeError } from "../src/errors.js";
import { SHA_256, SHA_384 } from "@browsercore/crypto";
import type { HashId } from "@browsercore/crypto";
import type { CipherSuite, ProtocolVersion } from "../src/types.js";
import { TLS_1_2, TLS_1_3 } from "../src/types.js";

describe("cipher-suite size mappings", () => {
    it("cipherSuiteToHash returns SHA-384 only for the AES-256 suite", () => {
        expect(cipherSuiteToHash("TLS_AES_256_GCM_SHA384")).toBe(SHA_384);
        expect(cipherSuiteToHash("TLS_AES_128_GCM_SHA256")).toBe(SHA_256);
        expect(cipherSuiteToHash("TLS_CHACHA20_POLY1305_SHA256")).toBe(SHA_256);
        expect(cipherSuiteToHash("TLS_AES_128_CCM_SHA256")).toBe(SHA_256);
    });

    it("cipherSuiteKeyLength distinguishes 16-byte (AES-128) from 32-byte (AES-256/ChaCha)", () => {
        expect(cipherSuiteKeyLength("TLS_AES_128_GCM_SHA256")).toBe(16);
        expect(cipherSuiteKeyLength("TLS_AES_128_CCM_SHA256")).toBe(16);
        expect(cipherSuiteKeyLength("TLS_AES_256_GCM_SHA384")).toBe(32);
        expect(cipherSuiteKeyLength("TLS_CHACHA20_POLY1305_SHA256")).toBe(32);
    });

    it("cipherSuiteIvLength is 12 for every suite", () => {
        for (const suite of [
            "TLS_AES_128_GCM_SHA256",
            "TLS_AES_256_GCM_SHA384",
            "TLS_CHACHA20_POLY1305_SHA256",
            "TLS_AES_128_CCM_SHA256",
        ] as readonly CipherSuite[]) {
            expect(cipherSuiteIvLength(suite)).toBe(12);
        }
    });
});

describe("hkdfExpandLabel", () => {
    it("produces exactly `length` bytes", () => {
        const secret = crypto.randomBytes(32);
        const out = hkdfExpandLabel(secret, "key", new Uint8Array(0), 42, SHA_256, crypto);
        expect(out.length).toBe(42);
    });

    it("is deterministic for a fixed secret/label/context", () => {
        const secret = new Uint8Array(32).fill(0x11);
        const ctx = new Uint8Array([0xaa, 0xbb]);
        const a = hkdfExpandLabel(secret, "iv", ctx, 12, SHA_256, crypto);
        const b = hkdfExpandLabel(secret, "iv", ctx, 12, SHA_256, crypto);
        expect(a).toEqual(b);
    });
});

describe("deriveTrafficSecrets", () => {
    it("derives a key and IV of the cipher-suite-specified sizes", () => {
        const trafficSecret = crypto.randomBytes(32);
        const secrets = deriveTrafficSecrets(trafficSecret, "TLS_AES_256_GCM_SHA384", SHA_384, crypto);
        expect(secrets.key.length).toBe(32);
        expect(secrets.iv.length).toBe(12);
    });
});

describe("deriveHandshakeSecrets", () => {
    it("returns a master secret and per-direction record-protection secrets", () => {
        const sharedSecret = crypto.randomBytes(32);
        const helloTranscript = crypto.sha256(new Uint8Array([0x01, 0x02, 0x03]));
        const { masterSecret, traffic } = deriveHandshakeSecrets(
            sharedSecret,
            helloTranscript,
            "TLS_AES_128_GCM_SHA256",
            crypto,
        );
        // Master secret length equals the hash length (32 for SHA-256).
        expect(masterSecret.length).toBe(32);
        expect(traffic.client.key.length).toBe(16);
        expect(traffic.client.iv.length).toBe(12);
        expect(traffic.server.key.length).toBe(16);
        expect(traffic.server.iv.length).toBe(12);
    });

    it("uses a 48-byte master secret for the SHA-384 suite", () => {
        const sharedSecret = crypto.randomBytes(32);
        const helloTranscript = crypto.sha384(new Uint8Array([0x05]));
        const { masterSecret, traffic } = deriveHandshakeSecrets(
            sharedSecret,
            helloTranscript,
            "TLS_AES_256_GCM_SHA384",
            crypto,
        );
        expect(masterSecret.length).toBe(48);
        expect(traffic.client.key.length).toBe(32);
    });
});

describe("deriveApplicationSecrets", () => {
    it("derives client and server application traffic secrets from the master secret", () => {
        const masterSecret = crypto.randomBytes(32);
        const handshakeTranscript = crypto.sha256(new Uint8Array([0x09]));
        const app = deriveApplicationSecrets(masterSecret, handshakeTranscript, "TLS_AES_128_GCM_SHA256", crypto);
        expect(app.client.key.length).toBe(16);
        expect(app.client.iv.length).toBe(12);
        expect(app.server.key.length).toBe(16);
        expect(app.server.iv.length).toBe(12);
    });
});

describe("updateTrafficSecrets (KeyUpdate)", () => {
    it("re-derives fresh key/iv from the current traffic secret", () => {
        const currentSecret = crypto.randomBytes(32);
        const next = updateTrafficSecrets(currentSecret, "TLS_AES_128_GCM_SHA256", crypto);
        expect(next.key.length).toBe(16);
        expect(next.iv.length).toBe(12);
        // The new secret must differ from a trivial re-use of the input.
        expect(next.key).not.toEqual(currentSecret.subarray(0, 16));
    });
});

describe("assertCipherSuiteOffered", () => {
    it("does nothing when the selected suite was offered", () => {
        expect(() => assertCipherSuiteOffered("TLS_AES_128_GCM_SHA256", ["TLS_AES_128_GCM_SHA256"])).not.toThrow();
    });

    it("throws TlsHandshakeError when the selected suite was not offered", () => {
        expect(() =>
            assertCipherSuiteOffered("TLS_AES_128_CCM_SHA256", ["TLS_AES_128_GCM_SHA256"]),
        ).toThrow(TlsHandshakeError);
    });
});

describe("assertVersionSupported", () => {
    it("accepts TLS 1.2 and TLS 1.3", () => {
        expect(() => assertVersionSupported(TLS_1_2)).not.toThrow();
        expect(() => assertVersionSupported(TLS_1_3)).not.toThrow();
    });

    it("throws TlsHandshakeError for an unsupported version", () => {
        const bad = { name: "TLS 1.0", wire: 0x0301 } as unknown as ProtocolVersion;
        expect(() => assertVersionSupported(bad)).toThrow(TlsHandshakeError);
        try {
            assertVersionSupported(bad);
        } catch (e) {
            const err = e as TlsHandshakeError;
            expect(err.cause?.message).toMatch(/unsupported protocol version/);
        }
    });
});

describe("hashLength exhaustiveness guard", () => {
    it("hkdfExpandLabel surfaces the assertNever default for an unknown hash", () => {
        // hashLength is a private helper reached through hkdfExpandLabel. Feeding
        // a HashId the switch does not handle exercises the exhaustiveness
        // default at runtime (the type system would reject it at compile time).
        const bogus = "SHA-999" as unknown as HashId;
        expect(() =>
            hkdfExpandLabel(crypto.randomBytes(32), "key", new Uint8Array(0), 16, bogus, crypto),
        ).toThrow(/Unexpected value/);
    });
});

describe("HKDF-Expand length overflow guard", () => {
    it("throws when the requested length exceeds 255 * hashLen", () => {
        const secret = crypto.randomBytes(32);
        // SHA-256 hashLen = 32, so the max is 255 * 32 = 8160.
        expect(() => hkdfExpandLabel(secret, "key", new Uint8Array(0), 8161, SHA_256, crypto)).toThrow(
            /exceeds maximum/,
        );
    });
});
