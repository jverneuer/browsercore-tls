/**
 * Regression tests for ClientHello extension ordering (@browsercore/tls).
 *
 * Pins the correct behavior of buildClientHelloExtensions():
 *   4. Extensions appear in the EXACT order the profile's `extensionOrder`
 *      specifies — this is the primary TLS fingerprinting signal, so the byte
 *      order on the wire is load-bearing. Before the fix, a hardcoded subset of
 *      5 extensions was emitted in a fixed order regardless of the profile.
 *   5. Changing `extensionOrder` changes the wire bytes — proving the encoder
 *      actually reads the config instead of emitting a static layout. Two
 *      different orderings must produce different wire output.
 *
 * A minimal, dependency-free config (no crypto needed for ordering assertions)
 * is used so the tests exercise only the ordering path.
 */

import { describe, it, expect } from "vitest";
import { createTestCryptoProvider } from "./test-helpers.js";

const crypto = createTestCryptoProvider();
import { buildClientHello } from "../src/handshake/client-hello.js";
import { ExtensionType } from "../src/extensions/extensions.js";
import { TLS_1_3 } from "../src/types.js";
import type { ClientHelloConfig, KeyPair } from "../src/types.js";

/**
 * Generate a single x25519 key pair for the key_share extension.
 *
 * The handshake driver filters to supported groups, so a single x25519 share
 * suffices to populate the key_share extension in these tests.
 */
async function x25519KeyPair(): Promise<readonly KeyPair[]> {
    const kp = crypto.x25519GenerateKeyPair();
    return [{ algorithm: "x25519", privateKey: kp.secretKey, publicKey: kp.publicKey }];
}

/**
 * Walk a serialized ClientHello to its length-prefixed extensions block and
 * parse each entry into its type + data, preserving emission order.
 *
 * Layout: handshake header(4) || version(2) + random(32) + session_id +
 *   cipher_suites + compression + extensions_len(2) + extensions.
 *
 * Each extension within is type(2) || data_len(2) || data.
 */
function parseExtensionTypes(hello: Uint8Array): readonly number[] {
    let o = 4; // handshake header: type(1) + length(3)
    o += 2 + 32; // legacy_version(2) + random(32)
    const sidLen = hello[o] ?? 0;
    o += 1 + sidLen; // session_id_len(1) + session_id
    const csLen = ((hello[o] ?? 0) << 8) | (hello[o + 1] ?? 0);
    o += 2 + csLen; // cipher_suites_len(2) + cipher_suites
    const compLen = hello[o] ?? 0;
    o += 1 + compLen; // compression_len(1) + compression
    const extLen = ((hello[o] ?? 0) << 8) | (hello[o + 1] ?? 0);
    o += 2; // extensions_len(2)

    const end = o + extLen;
    const types: number[] = [];
    while (o < end) {
        const type = ((hello[o] ?? 0) << 8) | (hello[o + 1] ?? 0);
        const dataLen = ((hello[o + 2] ?? 0) << 8) | (hello[o + 3] ?? 0);
        types.push(type);
        o += 4 + dataLen;
    }
    return types;
}

/** A minimal, well-formed config whose extensionOrder the tests override. */
function baseConfig(order: readonly number[], grease: boolean): ClientHelloConfig {
    return {
        cipherSuites: ["TLS_AES_128_GCM_SHA256"],
        extensionOrder: order,
        keyShareGroups: ["x25519"],
        signatureAlgorithms: ["ecdsa_secp256r1_sha256"],
        supportedVersions: [TLS_1_3],
        serverName: "example.com",
        alpnProtocols: ["h2"],
        grease,
    };
}

describe("Extensions appear in the exact order specified by the profile", () => {
    it("emits extensions in the exact order given by extensionOrder (no GREASE)", async () => {
        // Pre-fix: only 5 hardcoded extensions were emitted, ignoring the profile.
        const order = [
            ExtensionType.SERVER_NAME, // 0
            ExtensionType.SUPPORTED_VERSIONS, // 43
            ExtensionType.KEY_SHARE, // 51
        ];
        const hello = buildClientHello(baseConfig(order, false), await x25519KeyPair(), () => Math.random(), crypto);
        expect(parseExtensionTypes(hello)).toEqual([...order]);
    });

    it("emits all profile extensions, not a hardcoded subset of 5", async () => {
        // chrome-140 advertises 16 extensions in a specific order — the encoder
        // must emit all of them, in that order, not stop after 5.
        const order = [
            0, 10, 11, 13, 16, 17613, 18, 23, 27, 35, 41, 43, 45, 5, 51, 65281,
        ];
        const hello = buildClientHello(baseConfig(order, false), await x25519KeyPair(), () => Math.random(), crypto);
        expect(parseExtensionTypes(hello)).toEqual([...order]);
        expect(parseExtensionTypes(hello)).toHaveLength(16);
    });

    it("prepends a GREASE extension (0x0a0a) ahead of the profile order when grease=true", async () => {
        const order = [
            ExtensionType.SERVER_NAME,
            ExtensionType.SUPPORTED_VERSIONS,
            ExtensionType.KEY_SHARE,
        ];
        // Pin the per-connection sentinel deterministically (random()=0.0 -> 0x0a0a).
        const hello = buildClientHello(baseConfig(order, true), await x25519KeyPair(), () => 0.0, crypto);
        const types = parseExtensionTypes(hello);
        expect(types[0]).toBe(0x0a0a);
        expect(types.slice(1)).toEqual([...order]);
    });

    it("emits extensions in reversed order when the profile reverses them", async () => {
        // A profile that advertises extensions in reverse IANA order must produce
        // exactly that reverse order on the wire — the encoder is order-faithful.
        const forward = [
            ExtensionType.SERVER_NAME, // 0
            ExtensionType.SUPPORTED_GROUPS, // 10
            ExtensionType.SIGNATURE_ALGORITHMS, // 13
            ExtensionType.SUPPORTED_VERSIONS, // 43
            ExtensionType.KEY_SHARE, // 51
        ];
        const reversed = [...forward].reverse();
        const hello = buildClientHello(baseConfig(reversed, false), await x25519KeyPair(), () => Math.random(), crypto);
        expect(parseExtensionTypes(hello)).toEqual(reversed);
        // And it must NOT match the forward order.
        expect(parseExtensionTypes(hello)).not.toEqual(forward);
    });
});

describe("Changing extensionOrder changes the wire bytes", () => {
    it("two different extension orders produce different ClientHello bytes", async () => {
        // Proves the encoder reads extensionOrder rather than emitting a static
        // layout. Same cipher suites, same everything — only the order differs.
        const a = buildClientHello(
            baseConfig([ExtensionType.SERVER_NAME, ExtensionType.SUPPORTED_VERSIONS], false),
            await x25519KeyPair(),
            () => Math.random(),
            crypto,
        );
        const b = buildClientHello(
            baseConfig([ExtensionType.SUPPORTED_VERSIONS, ExtensionType.SERVER_NAME], false),
            await x25519KeyPair(),
            () => Math.random(),
            crypto,
        );
        // The wire bytes must differ. random(32) differs per call, so compare
        // only the extensions region deterministically by checking the parsed
        // order rather than the raw bytes.
        expect(parseExtensionTypes(a)).toEqual([ExtensionType.SERVER_NAME, ExtensionType.SUPPORTED_VERSIONS]);
        expect(parseExtensionTypes(b)).toEqual([ExtensionType.SUPPORTED_VERSIONS, ExtensionType.SERVER_NAME]);
        expect(parseExtensionTypes(a)).not.toEqual(parseExtensionTypes(b));
    });

    it("adding an extension to the order changes the wire layout", async () => {
        const two = buildClientHello(
            baseConfig([ExtensionType.SERVER_NAME, ExtensionType.SUPPORTED_VERSIONS], false),
            await x25519KeyPair(),
            () => Math.random(),
            crypto,
        );
        const three = buildClientHello(
            baseConfig(
                [ExtensionType.SERVER_NAME, ExtensionType.SUPPORTED_VERSIONS, ExtensionType.KEY_SHARE],
                false,
            ),
            await x25519KeyPair(),
            () => Math.random(),
            crypto,
        );
        expect(parseExtensionTypes(two)).toHaveLength(2);
        expect(parseExtensionTypes(three)).toHaveLength(3);
        expect(parseExtensionTypes(three)).toEqual([
            ExtensionType.SERVER_NAME,
            ExtensionType.SUPPORTED_VERSIONS,
            ExtensionType.KEY_SHARE,
        ]);
    });

    it("a profile that omits ALPN does not emit ALPN", async () => {
        // The old code unconditionally hardcoded ALPN. A profile whose
        // extensionOrder omits type 16 must not get ALPN on the wire.
        const order = [ExtensionType.SERVER_NAME, ExtensionType.SUPPORTED_VERSIONS, ExtensionType.KEY_SHARE];
        const hello = buildClientHello(baseConfig(order, false), await x25519KeyPair(), () => Math.random(), crypto);
        const types = parseExtensionTypes(hello);
        expect(types).not.toContain(ExtensionType.APPLICATION_LAYER_PROTOCOL_NEGOTIATION);
        expect(types).toEqual([...order]);
    });
});
