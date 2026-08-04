/**
 * Tests for post-quantum named groups in @browsercore/tls.
 *
 * Verifies that the post-quantum hybrid groups (X25519Kyber768, X25519MLKEM768,
 * Secp256r1MLKEM768, Secp384r1MLKEM1024) map to the correct IANA wire codes,
 * round-trip through the encoder/decoder, and that key-share generation for
 * these groups produces a classical X25519 (or secp256r1/secp384r1) key share
 * — matching real Chrome hybrid-mode behavior where the PQ group is advertised
 * in supported_groups but key_share carries only the classical component.
 */

import { describe, it, expect } from "vitest";
import { namedGroupToWire, wireToNamedGroup } from "../src/extensions/extensions.js";
import { generateKeyShares } from "../src/tls.js";

/** All post-quantum hybrid groups the TLS layer recognizes. */
const PQ_GROUPS = ["X25519Kyber768", "X25519MLKEM768", "Secp256r1MLKEM768", "Secp384r1MLKEM1024"] as const;

describe("post-quantum named groups", () => {
    describe("namedGroupToWire", () => {
        it("X25519Kyber768 wire code is 0x6399", () => {
            expect(namedGroupToWire("X25519Kyber768")).toBe(0x6399);
        });

        it("X25519MLKEM768 wire code is 0x11ec", () => {
            expect(namedGroupToWire("X25519MLKEM768")).toBe(0x11ec);
        });

        it("Secp256r1MLKEM768 wire code is 0x11eb", () => {
            expect(namedGroupToWire("Secp256r1MLKEM768")).toBe(0x11eb);
        });

        it("Secp384r1MLKEM1024 wire code is 0x1204", () => {
            expect(namedGroupToWire("Secp384r1MLKEM1024")).toBe(0x1204);
        });
    });

    describe("wire code round-trip", () => {
        it("round-trips every PQ group through namedGroupToWire -> wireToNamedGroup", () => {
            for (const g of PQ_GROUPS) {
                const wire = namedGroupToWire(g);
                expect(wireToNamedGroup(wire)).toBe(g);
            }
        });

        it("round-trips the classical groups as well (regression guard)", () => {
            const classical: ReadonlyArray<[string, number]> = [
                ["secp256r1", 0x0017],
                ["secp384r1", 0x0018],
                ["x25519", 0x001d],
                ["x448", 0x001e],
            ];
            for (const [g, wire] of classical) {
                expect(namedGroupToWire(g as any)).toBe(wire);
                expect(wireToNamedGroup(wire)).toBe(g);
            }
        });
    });

    describe("generateKeyShares (hybrid mode)", () => {
        it("X25519MLKEM768 produces a single X25519 key_share (32-byte public key)", async () => {
            const shares = await generateKeyShares(["X25519MLKEM768"]);
            expect(shares).toHaveLength(1);
            const kp = shares[0]!;
            expect(kp.algorithm).toBe("x25519");
            // X25519 public keys are always 32 bytes (RFC 7748).
            expect(kp.publicKey.length).toBe(32);
            expect(kp.privateKey.length).toBeGreaterThan(0);
        });

        it("X25519Kyber768 produces a single X25519 key_share (32-byte public key)", async () => {
            const shares = await generateKeyShares(["X25519Kyber768"]);
            expect(shares).toHaveLength(1);
            const kp = shares[0]!;
            expect(kp.algorithm).toBe("x25519");
            expect(kp.publicKey.length).toBe(32);
        });

        it("Secp256r1MLKEM768 produces a single secp256r1 key_share (65-byte uncompressed public key)", async () => {
            const shares = await generateKeyShares(["Secp256r1MLKEM768"]);
            expect(shares).toHaveLength(1);
            const kp = shares[0]!;
            expect(kp.algorithm).toBe("secp256r1");
            // Uncompressed form: 0x04 || 32-byte x || 32-byte y = 65 bytes.
            expect(kp.publicKey.length).toBe(65);
            expect(kp.publicKey[0]).toBe(0x04);
        });

        it("Secp384r1MLKEM1024 produces a single secp384r1 key_share (97-byte uncompressed public key)", async () => {
            const shares = await generateKeyShares(["Secp384r1MLKEM1024"]);
            expect(shares).toHaveLength(1);
            const kp = shares[0]!;
            expect(kp.algorithm).toBe("secp384r1");
            // Uncompressed form: 0x04 || 48-byte x || 48-byte y = 97 bytes.
            expect(kp.publicKey.length).toBe(97);
            expect(kp.publicKey[0]).toBe(0x04);
        });

        it("deduplicates the classical X25519 share when a PQ group is mixed with x25519", async () => {
            // A real profile orders PQ first, then x25519; the x25519 share must
            // not be emitted twice.
            const shares = await generateKeyShares(["X25519MLKEM768", "x25519"]);
            expect(shares).toHaveLength(1);
            expect(shares[0]!.algorithm).toBe("x25519");
        });

        it("emits one X25519 share across multiple X25519-based PQ groups", async () => {
            const shares = await generateKeyShares(["X25519Kyber768", "X25519MLKEM768"]);
            expect(shares).toHaveLength(1);
            expect(shares[0]!.algorithm).toBe("x25519");
        });

        it("emits distinct classical shares for PQ groups with different classical components", async () => {
            const shares = await generateKeyShares(["X25519MLKEM768", "Secp256r1MLKEM768"]);
            expect(shares).toHaveLength(2);
            const algorithms = shares.map((s) => s.algorithm).sort();
            expect(algorithms).toEqual(["secp256r1", "x25519"]);
        });
    });
});
