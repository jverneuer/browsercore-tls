/**
 * Tests for RFC 8446 §5 change_cipher_spec record filtering.
 *
 * Real TLS 1.3 servers send a `change_cipher_spec` record (content type 20)
 * between ServerHello and the encrypted flight for middlebox compatibility.
 * Per the RFC, clients MUST silently ignore it. These tests verify that
 * `readEncryptedHandshakeMessage` skips CCS records and returns the first
 * encrypted APPLICATION_DATA record that follows, without advancing the AEAD
 * sequence number for the skipped CCS record.
 */

import { describe, it, expect } from "vitest";
import { readEncryptedHandshakeMessage } from "../src/connection/handshake-messages.js";
import { xorNonce } from "../src/connection/record-layer.js";
import { ContentType, encryptRecord, serializeRecordHeader } from "../src/record/record.js";
import { TlsHandshakeError } from "../src/errors.js";
import { FakeTransport } from "./fake-transport.js";

// ---------------------------------------------------------------------------
// Test fixtures
// ---------------------------------------------------------------------------

const HS_TRAFFIC = {
    key: new Uint8Array(16).fill(0xde),
    iv: new Uint8Array(12).fill(0xf0),
};

function concatBytes(...chunks: Uint8Array[]): Uint8Array {
    const total = chunks.reduce((s, c) => s + c.length, 0);
    const out = new Uint8Array(total);
    let o = 0;
    for (const c of chunks) {
        out.set(c, o);
        o += c.length;
    }
    return out;
}

/** Build a minimal change_cipher_spec record: type=20, version=0x0303, fragment=[0x01]. */
function buildCcsRecord(): Uint8Array {
    const fragment = new Uint8Array([0x01]); // CCS payload is always a single 0x01 byte
    return concatBytes(serializeRecordHeader(ContentType.CHANGE_CIPHER_SPEC, fragment.length), fragment);
}

/** Encrypt a handshake message into a standalone APPLICATION_DATA record. */
function encryptHandshakeRecord(content: Uint8Array, seq: number): Uint8Array {
    const plaintext = new Uint8Array(content.length + 1);
    plaintext.set(content, 0);
    plaintext[content.length] = ContentType.HANDSHAKE; // inner type
    const header = serializeRecordHeader(ContentType.APPLICATION_DATA, plaintext.length + 16);
    const nonce = xorNonce(HS_TRAFFIC.iv, seq);
    const ciphertext = encryptRecord(plaintext, HS_TRAFFIC.key, nonce, header, "AES-128-GCM");
    return concatBytes(header, ciphertext);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("readEncryptedHandshakeMessage — CCS record filtering (RFC 8446 §5)", () => {
    it("skips a single leading CCS record and returns the encrypted handshake message", async () => {
        const body = new Uint8Array([0xaa, 0xbb, 0xcc]);
        const whole = new Uint8Array(4 + body.length);
        whole[0] = 8; // handshake type: EncryptedExtensions
        whole[3] = body.length;
        whole.set(body, 4);

        const ccs = buildCcsRecord();
        const encrypted = encryptHandshakeRecord(whole, 0);
        const stream = concatBytes(ccs, encrypted);

        const result = await readEncryptedHandshakeMessage(
            stream,
            new FakeTransport(),
            "AES-128-GCM",
            HS_TRAFFIC,
            0,
        );
        expect(result.whole).toEqual(whole);
        expect(result.body).toEqual(body);
        expect(result.readBuffer.length).toBe(0);
    });

    it("skips multiple consecutive CCS records before the encrypted record", async () => {
        const body = new Uint8Array([0x01, 0x02]);
        const whole = new Uint8Array(4 + body.length);
        whole[0] = 11; // handshake type: Certificate
        whole[3] = body.length;
        whole.set(body, 4);

        const ccs1 = buildCcsRecord();
        const ccs2 = buildCcsRecord();
        const encrypted = encryptHandshakeRecord(whole, 0);
        const stream = concatBytes(ccs1, ccs2, encrypted);

        const result = await readEncryptedHandshakeMessage(
            stream,
            new FakeTransport(),
            "AES-128-GCM",
            HS_TRAFFIC,
            0,
        );
        expect(result.whole).toEqual(whole);
        expect(result.body).toEqual(body);
    });

    it("does NOT advance the AEAD sequence number for skipped CCS records", async () => {
        // The AEAD nonce is derived from XOR-ing the sequence number into the IV.
        // If the implementation wrongly advanced seq for the CCS record, it would
        // decrypt with seq=1 and the auth tag would fail. Here we verify the
        // encrypted record is decrypted with seq=0 (the caller's initial value).
        const body = new Uint8Array([0x42]);
        const whole = new Uint8Array(4 + body.length);
        whole[3] = body.length;
        whole.set(body, 4);

        const ccs = buildCcsRecord();
        // Encrypt with seq=0 — if the implementation skips CCS but still uses
        // seq=0 (correct), decryption succeeds. If it incremented to seq=1
        // (wrong), the nonce is wrong and AEAD auth fails.
        const encrypted = encryptHandshakeRecord(whole, 0);
        const stream = concatBytes(ccs, encrypted);

        const result = await readEncryptedHandshakeMessage(
            stream,
            new FakeTransport(),
            "AES-128-GCM",
            HS_TRAFFIC,
            0,
        );
        expect(result.body).toEqual(body);
    });

    it("still throws when a non-CCS, non-APPLICATION_DATA record follows the CCS", async () => {
        const ccs = buildCcsRecord();
        // A handshake record (type 22) where an encrypted record is expected.
        const bad = concatBytes(
            serializeRecordHeader(ContentType.HANDSHAKE, 4),
            new Uint8Array(4),
        );
        const stream = concatBytes(ccs, bad);

        await expect(
            readEncryptedHandshakeMessage(stream, new FakeTransport(), "AES-128-GCM", HS_TRAFFIC, 0),
        ).rejects.toThrow(TlsHandshakeError);
    });

    it("leaves the remaining buffer positioned after the encrypted record", async () => {
        const body = new Uint8Array([0x11, 0x22]);
        const whole = new Uint8Array(4 + body.length);
        whole[3] = body.length;
        whole.set(body, 4);

        const ccs = buildCcsRecord();
        const encrypted = encryptHandshakeRecord(whole, 0);
        const trailing = new Uint8Array([0xff, 0xff, 0xff]); // leftover bytes (e.g. next record)
        const stream = concatBytes(ccs, encrypted, trailing);

        const result = await readEncryptedHandshakeMessage(
            stream,
            new FakeTransport(),
            "AES-128-GCM",
            HS_TRAFFIC,
            0,
        );
        expect(result.whole).toEqual(whole);
        // The leftover bytes after both the CCS and the encrypted record must
        // remain in the buffer for the caller to consume.
        expect(result.readBuffer).toEqual(trailing);
    });
});
