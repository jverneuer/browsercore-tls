/**
 * Tests for ClientHello record padding (RFC 7685 / RFC 8446 §4.1.2).
 *
 * Covers {@link computePaddingExtensionBody} — the pure function that decides
 * how many zero bytes the PADDING extension body must contain to reach a target
 * ClientHello message length. Tests both the "padding already in extension
 * order" and "padding appended at end" paths, plus the no-op cases.
 */

import { describe, it, expect } from "vitest";
import { computePaddingExtensionBody } from "../src/record/record-padding.js";
import { ExtensionType } from "../src/extensions/extensions.js";
import type { ClientHelloConfig } from "../src/types.js";

function config(overrides: Partial<ClientHelloConfig> = {}): ClientHelloConfig {
    return {
        cipherSuites: ["TLS_AES_128_GCM_SHA256"],
        extensionOrder: [0, 10, 11, 13, 16, 51],
        keyShareGroups: ["x25519"],
        signatureAlgorithms: ["ecdsa_secp256r1_sha256"],
        supportedVersions: [{ name: "TLS 1.3", wire: 0x0304 as const }],
        serverName: "example.com",
        grease: false,
        ...overrides,
    };
}

describe("computePaddingExtensionBody", () => {
    it("returns 0 when recordPadding is not set", () => {
        const cfg = config();
        expect(computePaddingExtensionBody(400, cfg)).toBe(0);
    });

    it("returns 0 when the message already meets the target", () => {
        const cfg = config({ recordPadding: 400 });
        expect(computePaddingExtensionBody(400, cfg)).toBe(0);
    });

    it("returns 0 when the message exceeds the target", () => {
        const cfg = config({ recordPadding: 300 });
        expect(computePaddingExtensionBody(400, cfg)).toBe(0);
    });

    it("computes body bytes when padding IS in the extension order", () => {
        // PADDING (21) is in extensionOrder → the probe already counts the
        // 4-byte PADDING header + 0-byte body. Body = target - probeSize.
        const cfg = config({
            recordPadding: 512,
            extensionOrder: [0, 10, 11, 13, 16, 51, ExtensionType.PADDING],
        });
        expect(computePaddingExtensionBody(400, cfg)).toBe(112);
    });

    it("accounts for the 4-byte header when padding is NOT in the extension order", () => {
        // PADDING (21) absent from extensionOrder → the extension will be
        // appended, adding 4 bytes of header. Body = target - probeSize - 4.
        const cfg = config({
            recordPadding: 512,
            extensionOrder: [0, 10, 11, 13, 16, 51],
        });
        expect(computePaddingExtensionBody(500, cfg)).toBe(8); // 512 - 500 - 4
    });

    it("returns 0 when the remaining budget after the header is negative", () => {
        // probeSize is 510, target 512, header 4 → body = 512 - 510 - 4 = -2 → 0.
        const cfg = config({
            recordPadding: 512,
            extensionOrder: [0, 10, 11, 13, 16, 51],
        });
        expect(computePaddingExtensionBody(510, cfg)).toBe(0);
    });
});
