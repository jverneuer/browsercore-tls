/**
 * Live-server TLS handshake regression test.
 *
 * Confirms the X25519 key-exchange fix works end-to-end against a real TLS
 * server. Gated behind RUN_LIVE_TESTS=1 so CI (which may have no network) stays
 * green — without the env var the suite is skipped entirely.
 *
 * The test drives the full TLS 1.3 handshake over a real TCP transport to
 * example.com:443 and asserts the connection reaches the "open" state with a
 * negotiated cipher suite. This is the ultimate regression guard: if the
 * X25519 shared-secret computation or the key-schedule derivation regresses,
 * the server's Finished MAC will not verify and the handshake will fail.
 */

import { describe, it, expect } from "vitest";
import { connect } from "@browsercore/transport";
import { createMockEventProvider, createTestCryptoProvider } from "./test-helpers.js";

const crypto = createTestCryptoProvider();
import { connectTls } from "../src/tls.js";
import { TLS_1_3 } from "../src/types.js";
import type { ClientHelloConfig } from "../src/types.js";

const RUN_LIVE_TESTS = process.env.RUN_LIVE_TESTS === "1";

/**
 * A minimal TLS 1.3 ClientHello profile offering X25519 key share.
 *
 * Deliberately minimal — the goal is to confirm the X25519 key exchange works
 * end-to-end, not to exercise every extension. Advertises the required
 * extensions for a TLS 1.3 handshake: SNI (0), supported_groups (10),
 * signature_algorithms (13), supported_versions (43), and key_share (51).
 */
const PROFILE: ClientHelloConfig = {
    cipherSuites: ["TLS_AES_128_GCM_SHA256"],
    extensionOrder: [0, 10, 13, 43, 51],
    keyShareGroups: ["x25519"],
    signatureAlgorithms: ["ecdsa_secp256r1_sha256"],
    supportedVersions: [TLS_1_3],
    serverName: "example.com",
    grease: false,
};

(RUN_LIVE_TESTS ? describe : describe.skip)("live TLS handshake", () => {
    it("completes a real handshake against example.com", async () => {
        // Open a real TCP connection to example.com:443.
        const transport = await connect({
            host: "example.com",
            port: 443,
            connectTimeoutMs: 15_000,
        });

        try {
            // Drive the full TLS 1.3 handshake over the live transport.
            const conn = await connectTls({
                transport,
                crypto,
                serverName: "example.com",
                profile: PROFILE,
                handshakeTimeoutMs: 25_000,
                events: createMockEventProvider(),
            });

            // The handshake reached the "open" state — ServerHello was received,
            // the X25519 shared secret was computed, the key schedule derived
            // traffic secrets, and the server's Finished MAC verified.
            expect(conn.state.state).toBe("open");
            expect(conn.protocolVersion).toEqual(TLS_1_3);
            expect(conn.cipherSuite).toBe("TLS_AES_128_GCM_SHA256");

            // Gracefully close the connection.
            await conn.close();
            expect(conn.state.state).toBe("closed");
        } finally {
            // Ensure the transport is torn down even if the assertions fail.
            await transport.close();
        }
    }, 30_000);
});
