/**
 * TLS record layer (RFC 8446 §5, RFC 5246 §6.2).
 *
 * Frames all higher-layer protocol messages (handshake, alert, change_cipher_spec,
 * application_data) into typed records. Encryption/decryption of the record
 * payload is delegated to @browsercore/crypto — this module owns framing only.
 */

import { crypto } from "@browsercore/crypto";
import type { AeadAlgorithm, CipherSuite } from "../types.js";
import { NotImplementedError, TlsDecryptError } from "../errors.js";
import { assertNever } from "../utils.js";

/** TLS record content types, per RFC 8446 §5.1. */
export const ContentType = {
    CHANGE_CIPHER_SPEC: 20,
    ALERT: 21,
    HANDSHAKE: 22,
    APPLICATION_DATA: 23,
} as const;

/** Union of valid content-type values. */
export type ContentType = (typeof ContentType)[keyof typeof ContentType];

/** On-the-wire record header (5 bytes). */
export interface RecordHeader {
    readonly type: ContentType;
    /** Legacy record version (0x0303 for TLS 1.2/1.3). */
    readonly version: number;
    /** Length of the fragment that follows (uint16). */
    readonly length: number;
}

/** A fully parsed record: header + (still possibly encrypted) fragment. */
export interface TlsRecord {
    readonly header: RecordHeader;
    readonly fragment: Uint8Array;
}

/** Size of a TLS record header in bytes. */
export const RECORD_HEADER_SIZE = 5 as const;

/** Maximum plaintext fragment length allowed by TLS (2^14). */
export const MAX_PLAINTEXT_FRAGMENT = 16_384 as const;

/**
 * Validate a raw byte as a known {@link ContentType}.
 *
 * Replaces the `raw[0] as ContentType` / `plaintext[end-1] as ContentType`
 * casts that pretended any number was a member of the union. Used by the record
 * layer to recover a typed content type from a raw header byte (and from the
 * trailing inner-type byte of a decrypted TLS 1.3 record).
 */
export function readContentType(byte: number): ContentType {
    switch (byte) {
        case ContentType.CHANGE_CIPHER_SPEC:
        case ContentType.ALERT:
        case ContentType.HANDSHAKE:
        case ContentType.APPLICATION_DATA:
            return byte;
        default:
            throw new TlsDecryptError("record", { cause: new Error(`invalid content type: ${byte}`) });
    }
}

/** Map a cipher suite to its AEAD algorithm. */
export function cipherSuiteToAead(cipherSuite: CipherSuite): AeadAlgorithm {
    switch (cipherSuite) {
        case "TLS_AES_128_GCM_SHA256":
            return "AES-128-GCM";
        case "TLS_AES_128_CCM_SHA256":
            // AES-128-CCM is a real TLS 1.3 cipher suite (RFC 8446), but
            // @browsercore/crypto exposes only AES-GCM and ChaCha20-Poly1305, so CCM
            // is never offered in any profile. Fail loudly if it ever reaches here
            // rather than silently substituting AES-128-GCM, which would let the
            // handshake complete and then fail every subsequent record decrypt.
            throw new NotImplementedError(
                "AES-128-CCM (TLS_AES_128_CCM_SHA256) — not backed by @browsercore/crypto",
            );
        case "TLS_AES_256_GCM_SHA384":
            return "AES-256-GCM";
        case "TLS_CHACHA20_POLY1305_SHA256":
            return "CHACHA20-POLY1305";
        default:
            return assertNever(cipherSuite);
    }
}

/**
 * Parse a 5-byte record header from the start of a buffer.
 * Throws {@link TlsDecryptError} if the buffer is too short.
 */
export function parseRecordHeader(buf: Uint8Array): RecordHeader {
    if (buf.length < RECORD_HEADER_SIZE) {
        throw new TlsDecryptError("record", {
            cause: new Error(`record header truncated: ${buf.length} < ${RECORD_HEADER_SIZE}`),
        });
    }
    const typeByte = buf[0];
    const b1 = buf[1];
    const b2 = buf[2];
    const b3 = buf[3];
    const b4 = buf[4];
    if (typeByte === undefined || b1 === undefined || b2 === undefined || b3 === undefined || b4 === undefined) {
        throw new TlsDecryptError("record", {
            cause: new Error(`record header truncated: ${buf.length} < ${RECORD_HEADER_SIZE}`),
        });
    }
    const type = readContentType(typeByte);
    const version = (b1 << 8) | b2;
    const length = (b3 << 8) | b4;
    return { type, version, length };
}

/**
 * Serialize a record header into a 5-byte buffer.
 *
 * @param type   Content type.
 * @param length Fragment length (must fit in uint16).
 * @param version Legacy record version, defaults to 0x0303.
 */
export function serializeRecordHeader(
    type: ContentType,
    length: number,
    version = 0x0303,
): Uint8Array {
    const out = new Uint8Array(RECORD_HEADER_SIZE);
    out[0] = type;
    out[1] = (version >> 8) & 0xff;
    out[2] = version & 0xff;
    out[3] = (length >> 8) & 0xff;
    out[4] = length & 0xff;
    return out;
}

/**
 * Encrypt a plaintext fragment with the negotiated AEAD algorithm.
 *
 * The TLS 1.3 record layer appends the inner content type to `plaintext` BEFORE
 * calling this function and uses the 5-byte record header as the AEAD
 * `additionalData`; this function is the pure AEAD step that delegates to
 * @browsercore/crypto. The outer record type (APPLICATION_DATA in TLS 1.3) is the
 * caller's responsibility.
 *
 * @param plaintext        Data to encrypt (caller has already appended the inner content type).
 * @param key              AEAD key for this direction.
 * @param nonce            Per-record nonce (already XOR'd with the sequence number).
 * @param additionalData   The 5-byte record header, used as the AEAD AAD.
 * @param algorithm        AEAD algorithm negotiated for this connection.
 */
export function encryptRecord(
    plaintext: Uint8Array,
    key: Uint8Array,
    nonce: Uint8Array,
    additionalData: Uint8Array,
    algorithm: AeadAlgorithm,
): Uint8Array {
    switch (algorithm) {
        case "AES-128-GCM":
            return crypto.aes128GcmEncrypt(key, nonce, plaintext, additionalData);
        case "AES-256-GCM":
            return crypto.aes256GcmEncrypt(key, nonce, plaintext, additionalData);
        case "CHACHA20-POLY1305":
            return crypto.chacha20Poly1305Encrypt(key, nonce, plaintext, additionalData);
        default:
            return assertNever(algorithm);
    }
}

/**
 * Decrypt a TLSCiphertext fragment with the negotiated AEAD algorithm.
 *
 * The TLS 1.3 record layer strips the trailing inner content type byte from the
 * returned plaintext and verifies it; this function is the pure AEAD step that
 * delegates to @browsercore/crypto, throwing {@link TlsDecryptError} on auth failure.
 *
 * @param ciphertext       Ciphertext with the 16-byte authentication tag appended.
 * @param key              AEAD key for this direction.
 * @param nonce            Per-record nonce (already XOR'd with the sequence number).
 * @param additionalData   The 5-byte record header, used as the AEAD AAD.
 * @param algorithm        AEAD algorithm negotiated for this connection.
 */
export function decryptRecord(
    ciphertext: Uint8Array,
    key: Uint8Array,
    nonce: Uint8Array,
    additionalData: Uint8Array,
    algorithm: AeadAlgorithm,
): Uint8Array {
    try {
        switch (algorithm) {
            case "AES-128-GCM":
                return crypto.aes128GcmDecrypt(key, nonce, ciphertext, additionalData);
            case "AES-256-GCM":
                return crypto.aes256GcmDecrypt(key, nonce, ciphertext, additionalData);
            case "CHACHA20-POLY1305":
                return crypto.chacha20Poly1305Decrypt(key, nonce, ciphertext, additionalData);
            default:
                return assertNever(algorithm);
        }
    } catch (cause) {
        // @browsercore/crypto throws its own DecryptError on auth failure; translate it
        // into the TLS-layer typed error so callers see a consistent error type.
        // Under exactOptionalPropertyTypes, `cause` must be `Error` (never undefined)
        // when passed in the options object — omit the key entirely otherwise.
        if (cause instanceof Error) {
            throw new TlsDecryptError(algorithm, { cause });
        }
        throw new TlsDecryptError(algorithm);
    }
}
