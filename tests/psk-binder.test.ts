/**
 * Regression tests for Plan 03: the PSK binder MUST be computed over the same
 * `random` that is emitted in the ClientHello on the wire.
 *
 * Background (RFC 8446 §4.2.11.2): the PSK binder is
 *   binder = HMAC(binder_key, Transcript-Hash(TruncatedClientHello))
 * where the truncated ClientHello is the full ClientHello with only the binder
 * values stripped. The server recomputes the binder over the random it received
 * in the ClientHello. If the client computed its binder over a DIFFERENT random
 * than the one on the wire, the two never match and every resumed / 0-RTT
 * handshake fails server verification.
 *
 * The bug (now fixed): serializeClientHelloBody() generated its own random for
 * the binder transcript, independent of the random buildClientHello() placed on
 * the wire. This test pins a fixed random, builds a resumed ClientHello, and
 * asserts the binder authenticates over exactly that random.
 */

import { describe, it, expect } from "vitest";
import { crypto } from "@browsercore/crypto";
import {
    buildClientHello,
    serializeClientHelloBody,
} from "../src/handshake/client-hello.js";
import {
    computeBinder,
    deriveBinderKey,
    deriveEarlySecretFromPsk,
    hashFor,
    hashLengthFor,
} from "../src/crypto/keySchedule.js";
import { ExtensionType } from "../src/extensions/extensions.js";
import { TLS_1_3 } from "../src/types.js";
import type { ClientHelloConfig, ClientHelloPskParams, KeyPair } from "../src/types.js";

/** Generate a single X25519 key pair for the key_share extension. */
async function keyPairX25519(): Promise<KeyPair> {
    const kp = crypto.x25519GenerateKeyPair();
    return { algorithm: "x25519" as const, privateKey: kp.secretKey, publicKey: kp.publicKey };
}

/**
 * A minimal ClientHello config that includes the PSK + PSK-mode extensions.
 * Accepts an optional `psk` so callers can build resumed handshakes.
 */
function baseConfig(psk?: ClientHelloPskParams): ClientHelloConfig {
    return {
        cipherSuites: ["TLS_AES_128_GCM_SHA256"],
        extensionOrder: [
            ExtensionType.SERVER_NAME,
            10, 11, 13, 16, 18, 23, 27, 35,
            ExtensionType.PRE_SHARED_KEY, // 41
            43,
            ExtensionType.PSK_KEY_EXCHANGE_MODES, // 45
            5,
            ExtensionType.KEY_SHARE, // 51
            65281,
        ],
        keyShareGroups: ["x25519"],
        signatureAlgorithms: ["ecdsa_secp256r1_sha256"],
        supportedVersions: [TLS_1_3],
        serverName: "example.com",
        grease: false,
        psk,
    };
}

/** A synthetic resumption PSK (32 bytes = SHA-256 hash length for AES-128-GCM). */
function testPskParams(): ClientHelloPskParams {
    return {
        psk: new Uint8Array(32).fill(0x11),
        cipherSuite: "TLS_AES_128_GCM_SHA256" as const,
        identity: new Uint8Array([0xde, 0xad, 0xbe, 0xef]),
        obfuscatedTicketAge: 12345678,
        offerEarlyData: false,
    };
}

/** A test PSK with 0-RTT intent (also emits the early_data extension). */
function testPskParamsEarlyData(): ClientHelloPskParams {
    return { ...testPskParams(), offerEarlyData: true };
}

/**
 * Extract the 32-byte random from a built ClientHello wire message.
 * Layout: handshake_type(1) + length(3) + legacy_version(2) + random(32) + ...
 */
function extractRandom(message: Uint8Array): Uint8Array {
    // Header: 1 (type) + 3 (length) + 2 (version) = 6 bytes before random.
    return message.subarray(6, 6 + 32);
}

describe("PSK binder random consistency (Plan 03)", () => {
    it("binder is computed over the same random as the ClientHello on the wire", async () => {
        // Use a MINIMAL extension order (only PRE_SHARED_KEY) so the truncated
        // binder transcript contains exactly the identities-only PSK extension
        // — which we can reconstruct exactly here and recompute the binder over
        // the PINNED random. With the old bug, buildClientHello and the binder
        // transcript used two independent randoms; recomputing over the wire
        // random would then NOT match the embedded binder.
        const fixedRandom = new Uint8Array(32).fill(0x42);
        const psk = testPskParams();
        const config: ClientHelloConfig = {
            cipherSuites: ["TLS_AES_128_GCM_SHA256"],
            extensionOrder: [ExtensionType.PRE_SHARED_KEY],
            keyShareGroups: ["x25519"],
            signatureAlgorithms: ["ecdsa_secp256r1_sha256"],
            supportedVersions: [TLS_1_3],
            serverName: "example.com",
            grease: false,
            psk,
        };
        const kp = await keyPairX25519();

        const message = buildClientHello(config, [kp], fixedRandom);

        // The random on the wire MUST be the one we provided.
        expect(extractRandom(message)).toEqual(fixedRandom);

        // Re-derive the binder using the SAME random and confirm it matches the
        // binder embedded in the message.
        const hash = hashFor(psk.cipherSuite);
        const binderKey = deriveBinderKey(deriveEarlySecretFromPsk(psk.psk, hash), hash);

        // Rebuild the truncated PSK extension (identities only) — this is the
        // only extension in the transcript for this minimal config.
        const identityLen = 2 + psk.identity.length + 4;
        const identitiesLen = 2 + identityLen;
        const idBody = new Uint8Array(identitiesLen);
        let o = 0;
        idBody[o++] = (identityLen >> 8) & 0xff;
        idBody[o++] = identityLen & 0xff;
        idBody[o++] = (psk.identity.length >> 8) & 0xff;
        idBody[o++] = psk.identity.length & 0xff;
        idBody.set(psk.identity, o);
        o += psk.identity.length;
        idBody[o++] = (psk.obfuscatedTicketAge >>> 24) & 0xff;
        idBody[o++] = (psk.obfuscatedTicketAge >>> 16) & 0xff;
        idBody[o++] = (psk.obfuscatedTicketAge >>> 8) & 0xff;
        idBody[o++] = psk.obfuscatedTicketAge & 0xff;
        const truncatedPskExt = (() => {
            const w = new Uint8Array(2 + 2 + idBody.length);
            w[0] = (ExtensionType.PRE_SHARED_KEY >> 8) & 0xff;
            w[1] = ExtensionType.PRE_SHARED_KEY & 0xff;
            w[2] = (idBody.length >> 8) & 0xff;
            w[3] = idBody.length & 0xff;
            w.set(idBody, 4);
            return w;
        })();
        // The extension block under the binder transcript is just the truncated
        // PSK extension (the implementation serializes the full body with all
        // extensions in order; here the order has only PSK).
        const truncatedBody = serializeClientHelloBody(config, [kp], truncatedPskExt, fixedRandom);
        const recomputedBinder = computeBinder(binderKey, truncatedBody, hash);

        // Extract the binder embedded in the built ClientHello and compare.
        const embeddedBinder = extractBinderFromMessage(message);
        expect(recomputedBinder).toEqual(embeddedBinder);
        expect(recomputedBinder.length).toBe(hashLengthFor(hash));
    });

    it("a different random produces a different binder (proves random is in the transcript)", async () => {
        const psk = testPskParams();
        const config = baseConfig(psk);
        const kp = await keyPairX25519();

        const randomA = new Uint8Array(32).fill(0x01);
        const randomB = new Uint8Array(32).fill(0x02);

        const msgA = buildClientHello(config, [kp], randomA);
        const msgB = buildClientHello(config, [kp], randomB);

        const binderA = extractBinderFromMessage(msgA);
        const binderB = extractBinderFromMessage(msgB);

        // Binders differ because the transcript (which includes random) differs.
        expect(binderA).not.toEqual(binderB);
        // And the wire randoms are the ones we supplied.
        expect(extractRandom(msgA)).toEqual(randomA);
        expect(extractRandom(msgB)).toEqual(randomB);
    });

    it("a fixed random yields a deterministic binder across builds", async () => {
        const psk = testPskParams();
        const config = baseConfig(psk);
        const kp = await keyPairX25519();
        const fixed = new Uint8Array(32).fill(0xab);

        const first = extractBinderFromMessage(buildClientHello(config, [kp], fixed));
        const second = extractBinderFromMessage(buildClientHello(config, [kp], fixed));

        expect(first).toEqual(second);
    });

    it("early_data PSK also authenticates over the wire random", async () => {
        const fixedRandom = new Uint8Array(32).fill(0x77);
        const psk = testPskParamsEarlyData();
        const config = baseConfig(psk);
        const kp = await keyPairX25519();

        const message = buildClientHello(config, [kp], fixedRandom);

        // Wire random must be the pinned one, even with early_data injected.
        expect(extractRandom(message)).toEqual(fixedRandom);

        // The embedded binder must be a valid-length HMAC for the PSK's hash.
        const hash = hashFor(psk.cipherSuite);
        const binder = extractBinderFromMessage(message);
        expect(binder.length).toBe(hashLengthFor(hash));
    });
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Locate and extract the PSK binder value from a built ClientHello wire message.
 *
 * Parses the extensions block to find the pre_shared_key extension (type 41),
 * then reads the binder_list and returns the first binder entry. Throws if the
 * structure is not found — a malformed build should fail the test loudly.
 */
function extractBinderFromMessage(message: Uint8Array): Uint8Array {
    // Skip handshake header (4 bytes) + version (2) + random (32) = 38 bytes.
    let o = 38;
    // session_id_len(1) + session_id (empty here).
    const sidLen = message[o] ?? 0;
    o += 1 + sidLen;
    // cipher_suites_len(2) + cipher_suites.
    const csLen = ((message[o] ?? 0) << 8) | (message[o + 1] ?? 0);
    o += 2 + csLen;
    // compression_len(1) + compression (null).
    const compLen = message[o] ?? 0;
    o += 1 + compLen;
    // extensions_len(2) + extensions.
    const extLen = ((message[o] ?? 0) << 8) | (message[o + 1] ?? 0);
    o += 2;
    const extEnd = o + extLen;

    while (o < extEnd) {
        const type = ((message[o] ?? 0) << 8) | (message[o + 1] ?? 0);
        const dataLen = ((message[o + 2] ?? 0) << 8) | (message[o + 3] ?? 0);
        const dataStart = o + 4;
        if (type === ExtensionType.PRE_SHARED_KEY) {
            return readFirstBinder(message.subarray(dataStart, dataStart + dataLen));
        }
        o = dataStart + dataLen;
    }
    throw new Error("pre_shared_key extension not found in ClientHello");
}

/**
 * Read the first binder entry from a pre_shared_key extension body.
 * Layout: identities_len(2) + identities || binders_len(2) + binder{ len(1) || value }.
 */
function readFirstBinder(body: Uint8Array): Uint8Array {
    let o = 0;
    const identitiesLen = ((body[o] ?? 0) << 8) | (body[o + 1] ?? 0);
    o += 2 + identitiesLen;
    const bindersLen = ((body[o] ?? 0) << 8) | (body[o + 1] ?? 0);
    o += 2;
    if (bindersLen === 0) {
        throw new Error("pre_shared_key extension has no binders");
    }
    const firstBinderLen = body[o] ?? 0;
    o += 1;
    return body.subarray(o, o + firstBinderLen);
}
