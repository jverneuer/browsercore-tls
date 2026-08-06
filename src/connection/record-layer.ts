/**
 * TLS record-layer I/O (RFC 8446 §5).
 *
 * Reading and writing records, and the AEAD encrypt/decrypt step that turns a
 * plaintext fragment into an encrypted record (and back). These are expressed
 * as pure functions over an explicit `readBuffer` + `transport` rather than as
 * methods reaching into private connection state — the class owns its fields and
 * threads the buffer through, while this module owns the byte mechanics.
 *
 * `readBuffer` is treated as an immutable input that each function consumes a
 * prefix of and returns the remainder as part of its result; the caller (the
 * connection) reassigns its buffer to that remainder. This keeps the framing
 * logic testable in isolation without exposing the buffer.
 */

import type { Transport } from "@browsercore/transport";
import type { CryptoProvider } from "@browsercore/crypto";
import type { TrafficSecrets } from "../types.js";
import { TlsDecryptError, TlsHandshakeError } from "../errors.js";
import { ContentType, decryptRecord, encryptRecord, parseRecordHeader, readContentType, serializeRecordHeader } from "../record/record.js";
/** AEAD authentication tag length for every cipher we support (bytes). */
export const AEAD_TAG_LENGTH = 16;

/** Concatenate byte chunks into a single buffer. */
export function concat(...chunks: readonly Uint8Array[]): Uint8Array {
    let total = 0;
    for (const c of chunks) {
        total += c.length;
    }
    const out = new Uint8Array(total);
    let o = 0;
    for (const c of chunks) {
        out.set(c, o);
        o += c.length;
    }
    return out;
}

/**
 * Build the per-record AEAD nonce by XOR-ing the (zero-padded, big-endian)
 * sequence number into the static IV — exactly TLS 1.3 §5.3.
 */
export function xorNonce(iv: Uint8Array, seq: number): Uint8Array {
    const nonce = Uint8Array.from(iv);
    let s = seq;
    for (let i = nonce.length - 1; i >= nonce.length - 8 && s > 0; i--) {
        // The loop bounds guarantee i is a valid index, but noUncheckedIndexedAccess
        // cannot see that — read through a local and guard before mutating.
        const byte = nonce[i];
        if (byte === undefined) {
            throw new TlsDecryptError("xor_nonce", {
                cause: new Error(`nonce index ${i} out of bounds (iv length ${nonce.length})`),
            });
        }
        nonce[i] = byte ^ (s & 0xff);
        s = Math.floor(s / 256);
    }
    return nonce;
}

/** Pull bytes from the transport until at least `n` are buffered. Returns the new buffer. */
export async function ensureBytes(readBuffer: Uint8Array, transport: Transport, n: number): Promise<Uint8Array> {
    let buffer = readBuffer;
    while (buffer.length < n) {
        // Sequential by necessity: each transport.read() delivers a variable
        // number of bytes and the loop continuation (buffer.length < n) must be
        // re-evaluated after every read, so the reads cannot be parallelized.
        // eslint-disable-next-line no-await-in-loop
        const chunk = await transport.read();
        buffer = concat(buffer, chunk);
    }
    return buffer;
}

/**
 * Read the 5-byte record header and return it raw (needed as AEAD AAD) plus the
 * parsed length and the buffer left after consuming the header.
 */
export async function readHeaderBytes(
    readBuffer: Uint8Array,
    transport: Transport,
): Promise<{ raw: Uint8Array; length: number; readBuffer: Uint8Array }> {
    const buffer = await ensureBytes(readBuffer, transport, 5);
    const raw = buffer.subarray(0, 5);
    const parsed = parseRecordHeader(raw);
    return { raw, length: parsed.length, readBuffer: buffer };
}

/** Read a complete record given its already-consumed header. Returns the new buffer. */
export async function readRawRecord(
    readBuffer: Uint8Array,
    transport: Transport,
    header: { raw: Uint8Array; length: number },
): Promise<{ type: ContentType; fragment: Uint8Array; readBuffer: Uint8Array }> {
    const buffer = await ensureBytes(readBuffer, transport, 5 + header.length);
    // type is byte 0 of the header; validate it back to the union (the cast that
    // used to live here is replaced by a properly-typed parse step).
    const typeByte = header.raw[0];
    if (typeByte === undefined) {
        throw new TlsDecryptError("record", { cause: new Error("record header missing content type byte") });
    }
    const type = readContentType(typeByte);
    const fragment = buffer.subarray(5, 5 + header.length);
    return { type, fragment, readBuffer: buffer.subarray(5 + header.length) };
}

/**
 * Read and decrypt one record, returning its inner content type and content.
 * TLS 1.3 wraps encrypted handshake messages in records whose outer type is
 * application_data; the real type is the last non-zero byte of the plaintext.
 */
export async function readEncryptedRecord(
    readBuffer: Uint8Array,
    transport: Transport,
    aead: Parameters<typeof encryptRecord>[4],
    traffic: TrafficSecrets,
    seq: number,
    provider: CryptoProvider,
): Promise<{ innerType: ContentType; content: Uint8Array; readBuffer: Uint8Array }> {
    const header = await readHeaderBytes(readBuffer, transport);
    const record = await readRawRecord(header.readBuffer, transport, header);
    if (record.type !== ContentType.APPLICATION_DATA) {
        throw new TlsHandshakeError("finished", {
            cause: new Error(`expected encrypted APPLICATION_DATA record, got ${record.type}`),
        });
    }
    const nonce = xorNonce(traffic.iv, seq);
    const plaintext = decryptRecord(record.fragment, traffic.key, nonce, header.raw, aead, provider)
    // plaintext = content || innerType || optional zero padding. Find the type.
    let end = plaintext.length;
    while (end > 0 && plaintext[end - 1] === 0) {
        end--;
    }
    if (end === 0) {
        throw new TlsHandshakeError("finished", {
            cause: new Error("encrypted record plaintext is all zero padding"),
        });
    }
    const innerTypeByte = plaintext[end - 1];
    if (innerTypeByte === undefined) {
        throw new TlsHandshakeError("finished", {
            cause: new Error("encrypted record plaintext ended before the inner content type byte"),
        });
    }
    const innerType = readContentType(innerTypeByte);
    return { innerType, content: plaintext.subarray(0, end - 1), readBuffer: record.readBuffer };
}

/** Write an unencrypted record (used for the initial ClientHello/ServerHello). */
export async function writeRecord(transport: Transport, type: ContentType, fragment: Uint8Array): Promise<void> {
    await transport.write(concat(serializeRecordHeader(type, fragment.length), fragment));
}

/**
 * Encrypt a payload under `traffic` and write it as an encrypted record whose
 * outer type is application_data. The inner content type byte is appended to
 * the plaintext before encryption.
 */
export function writeEncryptedRecord(
    transport: Transport,
    aead: Parameters<typeof encryptRecord>[4],
    traffic: TrafficSecrets,
    innerType: ContentType,
    content: Uint8Array,
    seq: number,
    provider: CryptoProvider,
): void {
    const plaintext = concat(content, new Uint8Array([innerType]));
    const header = serializeRecordHeader(ContentType.APPLICATION_DATA, plaintext.length + AEAD_TAG_LENGTH);
    const nonce = xorNonce(traffic.iv, seq);
    const ciphertext = encryptRecord(plaintext, traffic.key, nonce, header, aead, provider)
    void transport.write(concat(header, ciphertext));
}
