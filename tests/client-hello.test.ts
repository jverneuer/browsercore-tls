/**
 * Tests for @browsercore/tls ClientHello construction (RFC 8446 §4.2).
 *
 * The handshake.test.ts file covers buildClientHello's ALPN presence/absence
 * and the ALPN length guard. This file covers the remaining defensive guards
 * that only fire on a malformed config: an SNI server_name that exceeds the
 * 16-bit length prefix, and the per-index undefined checks for cipher suites,
 * supported versions, and signature algorithms. These branches are
 * unreachable from a well-typed caller but exist to satisfy
 * noUncheckedIndexedAccess without non-null assertions, so they are exercised
 * here with crafted configs.
 */

import { describe, it, expect } from "vitest";
import { crypto } from "@browsercore/crypto";
import { buildClientHello } from "../src/handshake/client-hello.js";
import { TlsHandshakeError } from "../src/errors.js";
import { TLS_1_3 } from "../src/types.js";
import type { ClientHelloConfig, KeyPair } from "../src/types.js";

async function keyPairs(groups: readonly string[]): Promise<readonly KeyPair[]> {
    const out: KeyPair[] = [];
    for (const g of groups) {
        const kp = crypto.x25519GenerateKeyPair();
        out.push({ algorithm: g as KeyPair["algorithm"], privateKey: kp.secretKey, publicKey: kp.publicKey });
    }
    return out;
}

const BASE_CONFIG: ClientHelloConfig = {
    cipherSuites: ["TLS_AES_128_GCM_SHA256"],
    extensionOrder: [
        0, 10, 11, 13, 16, 17513, 18, 23, 27, 35, 41, 43, 45, 5, 51, 65281,
    ],
    keyShareGroups: ["x25519"],
    signatureAlgorithms: ["ecdsa_secp256r1_sha256"],
    supportedVersions: [TLS_1_3],
    serverName: "example.com",
    grease: true,
};

describe("buildClientHello SNI length guard", () => {
    it("throws when the SNI server_name exceeds 65535 bytes", async () => {
        const kps = await keyPairs(["x25519"]);
        const huge = "a".repeat(65536);
        try {
            buildClientHello({ ...BASE_CONFIG, serverName: huge }, kps);
            expect.unreachable("expected a throw");
        } catch (e) {
            const err = e as TlsHandshakeError;
            expect(err).toBeInstanceOf(TlsHandshakeError);
            expect(err.phase).toBe("client_hello");
            expect(err.cause?.message).toMatch(/SNI server_name exceeds 65535/);
        }
    });

    it("builds when the SNI server_name is exactly 65535 bytes", async () => {
        const kps = await keyPairs(["x25519"]);
        const max = "a".repeat(65535);
        // Should not throw — the bound is inclusive.
        const hello = buildClientHello({ ...BASE_CONFIG, serverName: max }, kps);
        expect(hello[0]).toBe(0x01); // HandshakeType.CLIENT_HELLO
    });
});

describe("buildClientHello per-index undefined guards", () => {
    it("throws when a cipher suite entry is undefined", async () => {
        // config.cipherSuites is typed as a non-undefined array, but a caller
        // could pass one with a hole; the encoder must not silently emit 0x0000.
        const kps = await keyPairs(["x25519"]);
        const sparse = ["TLS_AES_128_GCM_SHA256", undefined as unknown as "TLS_AES_128_GCM_SHA256"];
        const cfg = { ...BASE_CONFIG, cipherSuites: sparse };
        try {
            buildClientHello(cfg, kps);
            expect.unreachable("expected a throw");
        } catch (e) {
            const err = e as TlsHandshakeError;
            expect(err.phase).toBe("client_hello");
            expect(err.cause?.message).toMatch(/cipher suite at index 1 is missing/);
        }
    });

    it("throws when a supported version entry is undefined", async () => {
        const kps = await keyPairs(["x25519"]);
        const sparse = [TLS_1_3, undefined as unknown as typeof TLS_1_3];
        const cfg = { ...BASE_CONFIG, supportedVersions: sparse };
        try {
            buildClientHello(cfg, kps);
            expect.unreachable("expected a throw");
        } catch (e) {
            const err = e as TlsHandshakeError;
            expect(err.cause?.message).toMatch(/supported version at index 1 is missing/);
        }
    });

    it("throws when a signature algorithm entry is undefined", async () => {
        const kps = await keyPairs(["x25519"]);
        const sparse = ["ecdsa_secp256r1_sha256", undefined as unknown as "ecdsa_secp256r1_sha256"];
        const cfg = { ...BASE_CONFIG, signatureAlgorithms: sparse };
        try {
            buildClientHello(cfg, kps);
            expect.unreachable("expected a throw");
        } catch (e) {
            const err = e as TlsHandshakeError;
            expect(err.cause?.message).toMatch(/signature algorithm at index 1 is missing/);
        }
    });
});
