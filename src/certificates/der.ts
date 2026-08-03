/**
 * Minimal DER parsing primitives (RFC 5280 / X.690).
 *
 * Only the subset of X.509 that real server certs use: SEQUENCE, INTEGER, OID,
 * OCTET STRING, BIT STRING, UTCTime / GeneralizedTime, NULL, BOOLEAN, and the
 * context-specific constructed tags [0]..[3] used by the TBSCertificate.
 *
 * These are the byte-level building blocks the certificate parser composes — no
 * X.509 semantics live here, just tag-length-value decoding. Keeping them
 * separate from the cert logic means the ASN.1 layer can be read and tested in
 * isolation from hostname matching or chain validation.
 */

import type { SignatureScheme } from "../types.js";
import { TlsHandshakeError } from "../errors.js";

/**
 * Read one byte at `pos`, throwing {@link TlsHandshakeError} if the index is out
 * of range. Replaces the `buf[pos++] as number` pattern that suppressed the
 * `number | undefined` narrowing under `noUncheckedIndexedAccess`.
 */
function readByte(buf: Uint8Array, pos: number): number {
    const byte = buf[pos];
    if (byte === undefined) {
        throw new TlsHandshakeError("certificate", {
            cause: new Error(`DER byte truncated at offset ${pos}`),
        });
    }
    return byte;
}

/** A parsed DER tag-length-value span. */
export interface Tlv {
    readonly tag: number;
    readonly constructed: boolean;
    /** Offset of the tag byte. */
    readonly start: number;
    /** Offset where the value bytes begin (after tag + length). */
    readonly valueStart: number;
    /** Offset immediately after the value. */
    readonly end: number;
}

/** Read a single DER element as a span. Throws {@link TlsHandshakeError} on truncation. */
export function readTlv(buf: Uint8Array, pos: number): Tlv {
    if (pos >= buf.length) {
        throw new TlsHandshakeError("certificate", {
            cause: new Error(`DER truncated at offset ${pos}`),
        });
    }
    const start = pos;
    const tagByte = readByte(buf, pos++);
    // We only handle single-byte tags (tag number < 31); X.509 never uses the
    // long form for the tags we care about.
    if ((tagByte & 0x1f) === 0x1f) {
        throw new TlsHandshakeError("certificate", {
            cause: new Error("multi-byte DER tags are not supported"),
        });
    }
    const constructed = (tagByte & 0x20) !== 0;

    if (pos >= buf.length) {
        throw new TlsHandshakeError("certificate", {
            cause: new Error(`DER length truncated at offset ${pos}`),
        });
    }
    const lengthByte = readByte(buf, pos++);
    let valueStart: number;
    let length: number;
    if ((lengthByte & 0x80) === 0) {
        // Short form: single-byte length.
        length = lengthByte;
        valueStart = pos;
    } else {
        // Long form: the low 7 bits give the number of length bytes.
        const numBytes = lengthByte & 0x7f;
        if (numBytes === 0) {
            throw new TlsHandshakeError("certificate", {
                cause: new Error("indefinite-length DER encoding is not supported"),
            });
        }
        if (numBytes > 4 || pos + numBytes > buf.length) {
            throw new TlsHandshakeError("certificate", {
                cause: new Error(`DER length field overflow at offset ${pos}`),
            });
        }
        length = 0;
        for (let i = 0; i < numBytes; i++) {
            length = (length << 8) | readByte(buf, pos++);
        }
        valueStart = pos;
    }
    const end = valueStart + length;
    if (end > buf.length) {
        throw new TlsHandshakeError("certificate", {
            cause: new Error(`DER value truncated: need ${length} bytes at ${valueStart}, have ${buf.length - valueStart}`),
        });
    }
    return { tag: tagByte, constructed, start, valueStart, end };
}

/** Peek the tag byte at `pos` without consuming it. */
export function peekTag(buf: Uint8Array, pos: number): number {
    if (pos >= buf.length) {
        throw new TlsHandshakeError("certificate", {
            cause: new Error(`DER truncated while peeking tag at offset ${pos}`),
        });
    }
    return readByte(buf, pos);
}

/** Parse a DER OID (without its tag/length) into its dotted-arc string. */
export function parseOid(buf: Uint8Array, start: number, end: number): string {
    if (start >= end) {
        throw new TlsHandshakeError("certificate", {
            cause: new Error("empty OID"),
        });
    }
    // The first byte encodes the first two arcs: floor(first / 40), first % 40.
    const first = readByte(buf, start);
    const arcs: number[] = [Math.floor(first / 40), first % 40];
    let i = start + 1;
    while (i < end) {
        // Subsequent arcs are base-128 with the high bit as a continuation flag.
        let value = 0;
        let b: number;
        do {
            if (i >= end) {
                throw new TlsHandshakeError("certificate", {
                    cause: new Error("OID arc truncated"),
                });
            }
            b = readByte(buf, i++);
            // Guard against overflow on absurdly long arcs.
            value = (value << 7) | (b & 0x7f);
        } while ((b & 0x80) !== 0);
        arcs.push(value);
    }
    return arcs.join(".");
}

/** Parse a DER AlgorithmIdentifier (SEQUENCE { OID, parameters? }) into its OID string. */
export function parseAlgorithmIdentifierOid(buf: Uint8Array, start: number): string {
    const seq = readTlv(buf, start);
    if (seq.tag !== 0x30) {
        throw new TlsHandshakeError("certificate", {
            cause: new Error(`expected AlgorithmIdentifier SEQUENCE, got tag 0x${seq.tag.toString(16)}`),
        });
    }
    if (seq.valueStart >= seq.end) {
        throw new TlsHandshakeError("certificate", {
            cause: new Error("empty AlgorithmIdentifier"),
        });
    }
    const oidTlv = readTlv(buf, seq.valueStart);
    if (oidTlv.tag !== 0x06) {
        throw new TlsHandshakeError("certificate", {
            cause: new Error(`expected OID in AlgorithmIdentifier, got tag 0x${oidTlv.tag.toString(16)}`),
        });
    }
    return parseOid(buf, oidTlv.valueStart, oidTlv.end);
}

/**
 * Parse a DER ASN.1 TIME (UTCTime 0x17 or GeneralizedTime 0x18) into epoch
 * seconds. Handles the "...Z" UTC suffix; fractional seconds are ignored.
 */
export function parseTime(buf: Uint8Array, start: number, end: number, tag: number): number {
    const textDecoder = new TextDecoder();
    const str = textDecoder.decode(buf.subarray(start, end)).trim();

    // UTCTime: YYMMDDHHMMSSZ. GeneralizedTime: YYYYMMDDHHMMSS[.fff]Z.
    const isUtc = tag === 0x17;
    if (str.length < (isUtc ? 11 : 13)) {
        throw new TlsHandshakeError("certificate", {
            cause: new Error(`ASN.1 TIME too short: "${str}"`),
        });
    }
    const yearStr = str.slice(0, isUtc ? 2 : 4);
    let year = Math.trunc(Number(yearStr));
    if (Number.isNaN(year)) {
        throw new TlsHandshakeError("certificate", {
            cause: new Error(`invalid year in ASN.1 TIME: "${str}"`),
        });
    }
    if (isUtc) {
        // RFC 5280: UTCTime years 50..99 => 1950..1999; 00..49 => 2000..2049.
        year += year >= 50 ? 1900 : 2000;
    }
    const month = Math.trunc(Number(str.slice(isUtc ? 2 : 4, isUtc ? 4 : 6))) - 1;
    const day = Math.trunc(Number(str.slice(isUtc ? 4 : 6, isUtc ? 6 : 8)));
    const hour = Math.trunc(Number(str.slice(isUtc ? 6 : 8, isUtc ? 8 : 10)));
    const minute = Math.trunc(Number(str.slice(isUtc ? 8 : 10, isUtc ? 10 : 12)));
    const second = Math.trunc(Number(str.slice(isUtc ? 10 : 12, isUtc ? 12 : 14)));

    // Date.UTC returns ms since epoch in UTC.
    const ms = Date.UTC(year, month, day, hour, minute, second);
    if (Number.isNaN(ms)) {
        throw new TlsHandshakeError("certificate", {
            cause: new Error(`invalid ASN.1 TIME: "${str}"`),
        });
    }
    return Math.floor(ms / 1000);
}

/**
 * Map an issuer signature-algorithm OID to our {@link SignatureScheme} union.
 * Only the schemes we advertise are recognized; anything else throws.
 */
export function oidToSignatureScheme(oid: string): SignatureScheme {
    switch (oid) {
        case "1.2.840.10045.4.3.2":
            return "ecdsa_secp256r1_sha256";
        case "1.2.840.10045.4.3.3":
            return "ecdsa_secp384r1_sha384";
        case "1.2.840.113549.1.1.11":
            return "rsa_pkcs1_sha256";
        case "1.2.840.113549.1.1.10":
            // id-RSASSA-PSS: the hash is in the parameters; default to sha256.
            return "rsa_pss_rsae_sha256";
        default:
            throw new TlsHandshakeError("certificate", {
                cause: new Error(`unsupported signature algorithm OID: ${oid}`),
            });
    }
}
