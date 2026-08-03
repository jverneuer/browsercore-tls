/**
 * Tests for @browsercore/tls connection record layer (RFC 8446 §5).
 *
 * Exercises the byte mechanics the connection class threads through:
 * concat, per-record nonce construction, buffered record reading, and the
 * encrypted record read/write round-trip. The AEAD primitives themselves are
 * already covered by record.test.ts — here we focus on the framing logic that
 * wraps them (header parsing, inner-type recovery, sequence threading).
 */

import { describe, it, expect } from "vitest";
import { crypto } from "@browsercore/crypto";
import { ContentType, serializeRecordHeader } from "../src/record/record.js";
import {
    TlsDecryptError,
    TlsHandshakeError,
} from "../src/errors.js";
import {
    concat,
    xorNonce,
    ensureBytes,
    readHeaderBytes,
    readRawRecord,
    readEncryptedRecord,
    writeRecord,
    writeEncryptedRecord,
    AEAD_TAG_LENGTH,
} from "../src/connection/record-layer.js";
import { FakeTransport } from "./fake-transport.js";

/** 16-byte AES-128 key + 12-byte IV, deterministic so nonces are predictable. */
const TRAFFIC = {
    key: new Uint8Array(16).fill(0xab),
    iv: new Uint8Array(12).fill(0xcd),
};

describe("concat", () => {
    it("returns an empty buffer for no chunks", () => {
        expect(concat()).toEqual(new Uint8Array(0));
    });

    it("returns a copy of a single chunk", () => {
        const a = new Uint8Array([1, 2, 3]);
        expect(concat(a)).toEqual(a);
    });

    it("concatenates multiple chunks in order", () => {
        const out = concat(new Uint8Array([1, 2]), new Uint8Array([3]), new Uint8Array([4, 5, 6]));
        expect(out).toEqual(new Uint8Array([1, 2, 3, 4, 5, 6]));
    });
});

describe("xorNonce", () => {
    it("leaves the IV unchanged for sequence number 0", () => {
        // seq 0 means the loop guard `s > 0` is false on entry — nothing is XOR'd.
        const iv = new Uint8Array(12).fill(0x01);
        const nonce = xorNonce(iv, 0);
        expect(nonce).toEqual(iv);
        // Returns a copy, not the input.
        expect(nonce).not.toBe(iv);
    });

    it("XORs the low byte of the sequence into the last IV byte", () => {
        const iv = new Uint8Array(12).fill(0x00);
        const nonce = xorNonce(iv, 1);
        expect(nonce[11]).toBe(1);
        // Bytes above the sequence's magnitude are untouched.
        expect(nonce[0]).toBe(0);
    });

    it("spreads a multi-byte sequence across the trailing 8 bytes (big-endian)", () => {
        const iv = new Uint8Array(12).fill(0x00);
        // 0x010203 occupies the last three bytes: ..., 0x01, 0x02, 0x03.
        const nonce = xorNonce(iv, 0x010203);
        expect(nonce[11]).toBe(0x03);
        expect(nonce[10]).toBe(0x02);
        expect(nonce[9]).toBe(0x01);
        expect(nonce[8]).toBe(0x00);
    });

    it("stops XOR-ing once the sequence magnitude is consumed", () => {
        const iv = new Uint8Array(12).fill(0xff);
        // seq = 0x0100 consumes two bytes (0x01, 0x00); the third byte from the
        // end is XOR'd with 0 (s becomes 0 after the high byte) so it is untouched.
        const nonce = xorNonce(iv, 0x0100);
        expect(nonce[11]).toBe(0xff); // 0xff ^ 0x00
        expect(nonce[10]).toBe(0xfe); // 0xff ^ 0x01
        expect(nonce[9]).toBe(0xff); // untouched
    });

    it("throws TlsDecryptError when the IV is too short for the sequence", () => {
        // A zero-length IV with a non-zero seq enters the loop with i = -1,
        // reading nonce[-1] which is undefined — the defensive guard fires.
        expect(() => xorNonce(new Uint8Array(0), 1)).toThrow(TlsDecryptError);
    });
});

describe("ensureBytes", () => {
    it("returns the buffer unchanged when it already has enough bytes", async () => {
        const buf = new Uint8Array(10);
        const transport = new FakeTransport();
        const result = await ensureBytes(buf, transport, 5);
        expect(result).toBe(buf); // same reference, no read needed
        expect(transport.readQueue.length).toBe(0);
    });

    it("pulls one chunk from the transport to reach the threshold", async () => {
        const buf = new Uint8Array(2);
        const transport = new FakeTransport();
        transport.readQueue.push(new Uint8Array([3, 4, 5]));
        const result = await ensureBytes(buf, transport, 5);
        expect(result).toEqual(new Uint8Array([0, 0, 3, 4, 5]));
    });

    it("pulls multiple chunks until the buffer is large enough", async () => {
        const buf = new Uint8Array(0);
        const transport = new FakeTransport();
        transport.readQueue.push(new Uint8Array([1, 2]), new Uint8Array([3]), new Uint8Array([4, 5]));
        const result = await ensureBytes(buf, transport, 5);
        expect(result).toEqual(new Uint8Array([1, 2, 3, 4, 5]));
    });
});

describe("readHeaderBytes", () => {
    it("parses a header already in the buffer without touching the transport", async () => {
        const header = serializeRecordHeader(ContentType.HANDSHAKE, 100);
        const transport = new FakeTransport();
        const { raw, length, readBuffer } = await readHeaderBytes(header, transport);
        expect(raw).toEqual(header);
        expect(length).toBe(100);
        expect(readBuffer).toBe(header); // whole buffer returned (header consumed by subarray in caller)
    });

    it("reads the header bytes from the transport when the buffer is short", async () => {
        const header = serializeRecordHeader(ContentType.APPLICATION_DATA, 50);
        const transport = new FakeTransport();
        transport.readQueue.push(header);
        const { raw, length } = await readHeaderBytes(new Uint8Array(0), transport);
        expect(raw).toEqual(header);
        expect(length).toBe(50);
    });
});

describe("readRawRecord", () => {
    it("returns the fragment and remainder after a complete record", async () => {
        const fragment = new Uint8Array([10, 20, 30]);
        const header = serializeRecordHeader(ContentType.HANDSHAKE, fragment.length);
        const buf = concat(header, fragment, new Uint8Array([99, 99])); // trailing bytes
        const transport = new FakeTransport();
        const { type, fragment: frag, readBuffer } = await readRawRecord(
            buf,
            transport,
            { raw: header, length: fragment.length },
        );
        expect(type).toBe(ContentType.HANDSHAKE);
        expect(frag).toEqual(fragment);
        expect(readBuffer).toEqual(new Uint8Array([99, 99]));
    });

    it("pulls the fragment body from the transport when incomplete", async () => {
        const fragment = new Uint8Array([1, 2, 3, 4]);
        const header = serializeRecordHeader(ContentType.APPLICATION_DATA, fragment.length);
        const transport = new FakeTransport();
        transport.readQueue.push(fragment); // body arrives via read()
        const { fragment: frag } = await readRawRecord(
            header, // only the header is buffered
            transport,
            { raw: header, length: fragment.length },
        );
        expect(frag).toEqual(fragment);
    });
});

describe("writeRecord", () => {
    it("writes a serialized header followed by the fragment", async () => {
        const transport = new FakeTransport();
        const fragment = new Uint8Array([1, 2, 3]);
        await writeRecord(transport, ContentType.HANDSHAKE, fragment);
        const out = transport.written[0]!;
        expect(out[0]).toBe(ContentType.HANDSHAKE);
        expect(out.subarray(5)).toEqual(fragment); // after the 5-byte header
    });
});

describe("writeEncryptedRecord + readEncryptedRecord round-trip", () => {
    it("round-trips an application_data record for AES-128-GCM", async () => {
        const transport = new FakeTransport();
        const content = new TextEncoder().encode("hello record layer");
        writeEncryptedRecord(
            transport,
            "AES-128-GCM",
            TRAFFIC,
            ContentType.APPLICATION_DATA,
            content,
            0,
        );
        const record = transport.written[0]!;
        // Outer type is application_data; length = plaintext + innerType + tag.
        expect(record[0]).toBe(ContentType.APPLICATION_DATA);
        const result = await readEncryptedRecord(
            record,
            new FakeTransport(),
            "AES-128-GCM",
            TRAFFIC,
            0,
        );
        expect(result.innerType).toBe(ContentType.APPLICATION_DATA);
        expect(result.content).toEqual(content);
    });

    it("round-trips for AES-256-GCM", async () => {
        const traffic = {
            key: new Uint8Array(32).fill(0x11),
            iv: new Uint8Array(12).fill(0x22),
        };
        const transport = new FakeTransport();
        const content = new TextEncoder().encode("aes-256");
        writeEncryptedRecord(transport, "AES-256-GCM", traffic, ContentType.HANDSHAKE, content, 7);
        const result = await readEncryptedRecord(
            transport.written[0]!,
            new FakeTransport(),
            "AES-256-GCM",
            traffic,
            7,
        );
        expect(result.innerType).toBe(ContentType.HANDSHAKE);
        expect(result.content).toEqual(content);
    });

    it("round-trips for ChaCha20-Poly1305", async () => {
        const traffic = {
            key: new Uint8Array(32).fill(0x33),
            iv: new Uint8Array(12).fill(0x44),
        };
        const transport = new FakeTransport();
        const content = new TextEncoder().encode("chacha");
        writeEncryptedRecord(
            transport,
            "CHACHA20-POLY1305",
            traffic,
            ContentType.APPLICATION_DATA,
            content,
            3,
        );
        const result = await readEncryptedRecord(
            transport.written[0]!,
            new FakeTransport(),
            "CHACHA20-POLY1305",
            traffic,
            3,
        );
        expect(result.content).toEqual(content);
    });

    it("strips trailing zero padding before the inner content type byte", async () => {
        // TLS 1.3 allows zero padding after the inner content type byte. The
        // plaintext layout is content || innerType || zeros. The reader must scan
        // backwards past the trailing zeros to find the real inner type byte.
        const content = new TextEncoder().encode("padded");
        const innerType = ContentType.APPLICATION_DATA;
        const padded = concat(content, new Uint8Array([innerType]), new Uint8Array(5).fill(0));
        const header = serializeRecordHeader(
            ContentType.APPLICATION_DATA,
            padded.length + AEAD_TAG_LENGTH,
        );
        const nonce = xorNonce(TRAFFIC.iv, 0);
        const ciphertext = crypto.aes128GcmEncrypt(TRAFFIC.key, nonce, padded, header);
        const record = concat(header, ciphertext);

        const result = await readEncryptedRecord(record, new FakeTransport(), "AES-128-GCM", TRAFFIC, 0);
        expect(result.innerType).toBe(innerType);
        expect(result.content).toEqual(content);
    });

    it("throws TlsHandshakeError when the outer record type is not application_data", async () => {
        // A plaintext handshake record where an encrypted one is expected.
        const transport = new FakeTransport();
        await writeRecord(transport, ContentType.HANDSHAKE, new Uint8Array([1, 2, 3]));
        await expect(
            readEncryptedRecord(transport.written[0]!, new FakeTransport(), "AES-128-GCM", TRAFFIC, 0),
        ).rejects.toThrow(TlsHandshakeError);
    });

    it("throws TlsHandshakeError when the decrypted plaintext is all zero padding", async () => {
        // Encrypt an all-zero plaintext: the inner-type scan reaches end === 0.
        const zeros = new Uint8Array(4).fill(0);
        const header = serializeRecordHeader(ContentType.APPLICATION_DATA, zeros.length + AEAD_TAG_LENGTH);
        const nonce = xorNonce(TRAFFIC.iv, 0);
        const ciphertext = crypto.aes128GcmEncrypt(TRAFFIC.key, nonce, zeros, header);
        const record = concat(header, ciphertext);
        await expect(
            readEncryptedRecord(record, new FakeTransport(), "AES-128-GCM", TRAFFIC, 0),
        ).rejects.toThrow(TlsHandshakeError);
    });

    it("throws TlsDecryptError when the inner content type byte is invalid", async () => {
        // Encrypt a plaintext whose last byte (the inner type) is 99 — not a
        // valid ContentType. readContentType rejects it.
        const bad = new Uint8Array([99]);
        const header = serializeRecordHeader(ContentType.APPLICATION_DATA, bad.length + AEAD_TAG_LENGTH);
        const nonce = xorNonce(TRAFFIC.iv, 0);
        const ciphertext = crypto.aes128GcmEncrypt(TRAFFIC.key, nonce, bad, header);
        const record = concat(header, ciphertext);
        await expect(
            readEncryptedRecord(record, new FakeTransport(), "AES-128-GCM", TRAFFIC, 0),
        ).rejects.toThrow(TlsDecryptError);
    });

    it("throws TlsDecryptError on authentication failure (wrong key)", async () => {
        const transport = new FakeTransport();
        writeEncryptedRecord(
            transport,
            "AES-128-GCM",
            TRAFFIC,
            ContentType.APPLICATION_DATA,
            new TextEncoder().encode("secret"),
            0,
        );
        const wrongTraffic = { key: new Uint8Array(16).fill(0x00), iv: TRAFFIC.iv };
        await expect(
            readEncryptedRecord(transport.written[0]!, new FakeTransport(), "AES-128-GCM", wrongTraffic, 0),
        ).rejects.toThrow(TlsDecryptError);
    });
});
