/**
 * Tests for @browsercore/tls connection key-exchange helpers.
 *
 * computeSharedSecret, transcriptHash, and verifyServerFinished — the
 * cryptographic core of the handshake. We drive the happy paths with real
 * X25519 key pairs (the only group the crypto backend supports) and cover every
 * malformed-ServerHello and transcript-mismatch branch with canned bytes.
 */

import { describe, it, expect } from "vitest";
import { crypto } from "@browsercore/crypto";
import { computeSharedSecret, transcriptHash, verifyServerFinished } from "../src/connection/key-exchange.js";
import { hkdfExpandLabel, hashLengthFor } from "../src/crypto/keySchedule.js";
import { TlsHandshakeError } from "../src/errors.js";
import { ExtensionType, namedGroupToWire } from "../src/extensions/extensions.js";
import { TLS_1_3 } from "../src/types.js";
import type { KeyPair, ServerHello } from "../src/handshake/handshake.js";

/** Build a ServerHello whose extensions block contains one key_share entry. */
function serverHelloWithKeyShare(groupWire: number, serverPublicKey: Uint8Array): ServerHello {
    // key_share extension body: group(2) || len(2) || key_exchange.
    const ksBody = new Uint8Array(4 + serverPublicKey.length);
    ksBody[0] = (groupWire >> 8) & 0xff;
    ksBody[1] = groupWire & 0xff;
    ksBody[2] = (serverPublicKey.length >> 8) & 0xff;
    ksBody[3] = serverPublicKey.length & 0xff;
    ksBody.set(serverPublicKey, 4);
    // Wrap in a length-prefixed extensions block.
    const ext = new Uint8Array(2 + 2 + 2 + ksBody.length);
    ext[0] = 0x00;
    ext[1] = (2 + 2 + ksBody.length) & 0xff; // extensions_len (fits in low byte)
    ext[2] = (ExtensionType.KEY_SHARE >> 8) & 0xff;
    ext[3] = ExtensionType.KEY_SHARE & 0xff;
    ext[4] = (ksBody.length >> 8) & 0xff;
    ext[5] = ksBody.length & 0xff;
    ext.set(ksBody, 6);
    return {
        protocolVersion: 0x0303,
        random: new Uint8Array(32),
        sessionId: new Uint8Array(0),
        cipherSuite: "TLS_AES_128_GCM_SHA256",
        compressionMethod: 0,
        selectedVersion: TLS_1_3,
        extensions: ext,
    };
}

/** Build a length-prefixed extensions block holding a truncated key_share body. */
function serverHelloWithRawKeyShareData(data: Uint8Array): ServerHello {
    const ext = new Uint8Array(2 + 2 + 2 + data.length);
    ext[0] = 0x00;
    ext[1] = (2 + 2 + data.length) & 0xff;
    ext[2] = (ExtensionType.KEY_SHARE >> 8) & 0xff;
    ext[3] = ExtensionType.KEY_SHARE & 0xff;
    ext[4] = (data.length >> 8) & 0xff;
    ext[5] = data.length & 0xff;
    ext.set(data, 6);
    return {
        protocolVersion: 0x0303,
        random: new Uint8Array(32),
        sessionId: new Uint8Array(0),
        cipherSuite: "TLS_AES_128_GCM_SHA256",
        compressionMethod: 0,
        selectedVersion: TLS_1_3,
        extensions: ext,
    };
}

describe("computeSharedSecret", () => {
    it("recovers the X25519 shared secret from the server's key share", () => {
        const client = crypto.x25519GenerateKeyPair();
        const server = crypto.x25519GenerateKeyPair();
        const keyPairs: KeyPair[] = [
            { algorithm: "x25519", privateKey: client.secretKey, publicKey: client.publicKey },
        ];
        const sh = serverHelloWithKeyShare(namedGroupToWire("x25519"), server.publicKey);
        const shared = computeSharedSecret(sh, keyPairs);
        const expected = crypto.x25519SharedSecret(client.secretKey, server.publicKey);
        expect(shared).toEqual(expected);
    });

    it("throws when the ServerHello has no key_share extension", () => {
        const client = crypto.x25519GenerateKeyPair();
        const keyPairs: KeyPair[] = [
            { algorithm: "x25519", privateKey: client.secretKey, publicKey: client.publicKey },
        ];
        // Empty extensions block.
        const sh: ServerHello = {
            protocolVersion: 0x0303,
            random: new Uint8Array(32),
            sessionId: new Uint8Array(0),
            cipherSuite: "TLS_AES_128_GCM_SHA256",
            compressionMethod: 0,
            selectedVersion: TLS_1_3,
            extensions: new Uint8Array([0x00, 0x00]),
        };
        expect(() => computeSharedSecret(sh, keyPairs)).toThrow(TlsHandshakeError);
        try {
            computeSharedSecret(sh, keyPairs);
        } catch (e) {
            expect((e as TlsHandshakeError).cause?.message).toMatch(/missing required key_share/);
        }
    });

    it("throws when the key_share entry is truncated (< 4 header bytes)", () => {
        const client = crypto.x25519GenerateKeyPair();
        const keyPairs: KeyPair[] = [
            { algorithm: "x25519", privateKey: client.secretKey, publicKey: client.publicKey },
        ];
        const sh = serverHelloWithRawKeyShareData(new Uint8Array([0x00, 0x1d])); // group only, no len
        expect(() => computeSharedSecret(sh, keyPairs)).toThrow(TlsHandshakeError);
    });

    it("throws when the key_exchange length does not match the remaining data", () => {
        const client = crypto.x25519GenerateKeyPair();
        const keyPairs: KeyPair[] = [
            { algorithm: "x25519", privateKey: client.secretKey, publicKey: client.publicKey },
        ];
        // group=x25519, len=32, but only 10 bytes of key follow.
        const sh = serverHelloWithRawKeyShareData(
            new Uint8Array([0x00, 0x1d, 0x00, 0x20, ...new Array(10).fill(0)]),
        );
        expect(() => computeSharedSecret(sh, keyPairs)).toThrow(TlsHandshakeError);
        try {
            computeSharedSecret(sh, keyPairs);
        } catch (e) {
            expect((e as TlsHandshakeError).cause?.message).toMatch(/length mismatch/);
        }
    });

    it("throws when the server selects a group the client did not offer", () => {
        const client = crypto.x25519GenerateKeyPair();
        // Client offers no key pairs at all.
        const sh = serverHelloWithKeyShare(namedGroupToWire("x25519"), client.publicKey);
        expect(() => computeSharedSecret(sh, [])).toThrow(TlsHandshakeError);
        try {
            computeSharedSecret(sh, []);
        } catch (e) {
            expect((e as TlsHandshakeError).cause?.message).toMatch(/we did not offer/);
        }
    });

    it("throws for a group the crypto backend cannot compute (secp256r1)", () => {
        // The backend exposes only X25519 shared-secret; secp256r1 must fail fast.
        const client = crypto.x25519GenerateKeyPair();
        const keyPairs: KeyPair[] = [
            { algorithm: "x25519", privateKey: client.secretKey, publicKey: client.publicKey },
            // Pretend the client also offered secp256r1 (so "did not offer" doesn't fire first).
            { algorithm: "secp256r1", privateKey: new Uint8Array(32), publicKey: new Uint8Array(65) },
        ];
        const sh = serverHelloWithKeyShare(namedGroupToWire("secp256r1"), new Uint8Array(65));
        expect(() => computeSharedSecret(sh, keyPairs)).toThrow(TlsHandshakeError);
        try {
            computeSharedSecret(sh, keyPairs);
        } catch (e) {
            expect((e as TlsHandshakeError).cause?.message).toMatch(/not supported by the crypto backend/);
        }
    });
});

describe("transcriptHash", () => {
    it("hashes the concatenated transcript with SHA-256", () => {
        const msg1 = new Uint8Array([1, 2, 3]);
        const msg2 = new Uint8Array([4, 5]);
        const blob = new Uint8Array([1, 2, 3, 4, 5]);
        const result = transcriptHash([msg1, msg2], "SHA-256");
        expect(result).toEqual(crypto.sha256(blob));
    });

    it("hashes the concatenated transcript with SHA-384", () => {
        const msg1 = new Uint8Array([1, 2, 3]);
        const msg2 = new Uint8Array([4, 5]);
        const blob = new Uint8Array([1, 2, 3, 4, 5]);
        const result = transcriptHash([msg1, msg2], "SHA-384");
        expect(result).toEqual(crypto.sha384(blob));
    });

    it("returns the hash of an empty blob for an empty transcript", () => {
        expect(transcriptHash([], "SHA-256")).toEqual(crypto.sha256(new Uint8Array(0)));
    });
});

describe("verifyServerFinished", () => {
    // Build a correct verify_data using the same formula the verifier uses, so
    // the happy path confirms and a mutated body fails.
    function makeFinished(
        hash: "SHA-256" | "SHA-384",
        transcript: Uint8Array,
        serverHsTrafficSecret: Uint8Array,
    ): Uint8Array {
        const hashLen = hashLengthFor(hash);
        const finishedKey = hkdfExpandLabel(serverHsTrafficSecret, "finished", new Uint8Array(0), hashLen, hash);
        return crypto.hmac(hash, finishedKey, transcript);
    }

    it("accepts a Finished whose verify_data matches the transcript (SHA-256)", () => {
        const secret = new Uint8Array(32).fill(0x5a);
        const transcript = new Uint8Array([10, 20, 30]);
        const body = makeFinished("SHA-256", transcript, secret);
        expect(() => verifyServerFinished(body, transcript, "SHA-256", secret)).not.toThrow();
    });

    it("accepts a Finished whose verify_data matches the transcript (SHA-384)", () => {
        const secret = new Uint8Array(48).fill(0x6b);
        const transcript = new Uint8Array([1, 2, 3, 4]);
        const body = makeFinished("SHA-384", transcript, secret);
        expect(() => verifyServerFinished(body, transcript, "SHA-384", secret)).not.toThrow();
    });

    it("throws when the Finished body length does not match the hash length", () => {
        const secret = new Uint8Array(32).fill(0x5a);
        const transcript = new Uint8Array([10, 20, 30]);
        // SHA-256 expects 32 bytes; pass 31.
        const wrong = new Uint8Array(31);
        expect(() => verifyServerFinished(wrong, transcript, "SHA-256", secret)).toThrow(TlsHandshakeError);
        try {
            verifyServerFinished(wrong, transcript, "SHA-256", secret);
        } catch (e) {
            expect((e as TlsHandshakeError).cause?.message).toMatch(/Finished length 31/);
        }
    });

    it("throws when the verify_data does not match the transcript", () => {
        const secret = new Uint8Array(32).fill(0x5a);
        const transcript = new Uint8Array([10, 20, 30]);
        const body = makeFinished("SHA-256", transcript, secret);
        // Flip a byte so the HMAC no longer matches.
        body[0] ^= 0xff;
        expect(() => verifyServerFinished(body, transcript, "SHA-256", secret)).toThrow(TlsHandshakeError);
        try {
            verifyServerFinished(body, transcript, "SHA-256", secret);
        } catch (e) {
            expect((e as TlsHandshakeError).cause?.message).toMatch(/verify_data mismatch/);
        }
    });
});
