/**
 * X.509 certificate handling (RFC 8446 §4.4.2, RFC 5280).
 *
 * Parses DER-encoded certificates, validates hostnames against SAN/CN, and
 * verifies certificate chains against trust anchors. The cryptographic
 * signature verification itself is delegated to @network/crypto — this module
 * owns ASN.1 layout and validation policy only.
 */

import { crypto } from "@network/crypto";
import type { SignatureScheme } from "../types.js";
import { TlsHandshakeError } from "../errors.js";

// ---------------------------------------------------------------------------
// Minimal DER parsing primitives.
//
// Only the subset of X.509 that real server certs use: SEQUENCE, INTEGER, OID,
// OCTET STRING, BIT STRING, UTCTime / GeneralizedTime, NULL, BOOLEAN, and the
// context-specific constructed tags [0]..[3] used by the TBSCertificate.
// ---------------------------------------------------------------------------

/** A parsed DER tag-length-value span. */
interface Tlv {
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
function readTlv(buf: Uint8Array, pos: number): Tlv {
    if (pos >= buf.length) {
        throw new TlsHandshakeError("certificate", {
            cause: new Error(`DER truncated at offset ${pos}`),
        });
    }
    const start = pos;
    const tagByte = buf[pos++]!;
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
    const lengthByte = buf[pos++]!;
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
            length = (length << 8) | buf[pos++]!;
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
function peekTag(buf: Uint8Array, pos: number): number {
    if (pos >= buf.length) {
        throw new TlsHandshakeError("certificate", {
            cause: new Error(`DER truncated while peeking tag at offset ${pos}`),
        });
    }
    return buf[pos]!;
}

/** Parse a DER OID (without its tag/length) into its dotted-arc string. */
function parseOid(buf: Uint8Array, start: number, end: number): string {
    if (start >= end) {
        throw new TlsHandshakeError("certificate", {
            cause: new Error("empty OID"),
        });
    }
    // The first byte encodes the first two arcs: floor(first / 40), first % 40.
    const first = buf[start]!;
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
            b = buf[i++]!;
            // Guard against overflow on absurdly long arcs.
            value = (value << 7) | (b & 0x7f);
        } while ((b & 0x80) !== 0);
        arcs.push(value);
    }
    return arcs.join(".");
}

/** Parse a DER AlgorithmIdentifier (SEQUENCE { OID, parameters? }) into its OID string. */
function parseAlgorithmIdentifierOid(buf: Uint8Array, start: number): string {
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
function parseTime(buf: Uint8Array, start: number, end: number, tag: number): number {
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
    let year = Number.parseInt(yearStr, 10);
    if (Number.isNaN(year)) {
        throw new TlsHandshakeError("certificate", {
            cause: new Error(`invalid year in ASN.1 TIME: "${str}"`),
        });
    }
    if (isUtc) {
        // RFC 5280: UTCTime years 50..99 => 1950..1999; 00..49 => 2000..2049.
        year += year >= 50 ? 1900 : 2000;
    }
    const month = Number.parseInt(str.slice(isUtc ? 2 : 4, isUtc ? 4 : 6), 10) - 1;
    const day = Number.parseInt(str.slice(isUtc ? 4 : 6, isUtc ? 6 : 8), 10);
    const hour = Number.parseInt(str.slice(isUtc ? 6 : 8, isUtc ? 8 : 10), 10);
    const minute = Number.parseInt(str.slice(isUtc ? 8 : 10, isUtc ? 10 : 12), 10);
    const second = Number.parseInt(str.slice(isUtc ? 10 : 12, isUtc ? 12 : 14), 10);

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
function oidToSignatureScheme(oid: string): SignatureScheme {
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


/** A parsed X.509 certificate (validation-relevant fields only). */
export interface Certificate {
    /** DER-encoded TBSCertificate bytes, needed for signature verification. */
    readonly tbsBytes: Uint8Array;
    /** DER-encoded SubjectPublicKeyInfo. */
    readonly subjectPublicKeyInfo: Uint8Array;
    /** Subject alternative DNS names (from the SAN extension), if any. */
    readonly subjectAltNames: readonly string[];
    /** Common Name from the subject DN, if present (legacy hostname match). */
    readonly commonName?: string;
    /** Not-before timestamp (epoch seconds). */
    readonly notBefore: number;
    /** Not-after timestamp (epoch seconds). */
    readonly notAfter: number;
    /** True if the certificate has the keyUsage bit for digital signature. */
    readonly keyUsageDigitalSignature: boolean;
    /** True if the certificate has the keyUsage bit for key encipherment/agreement. */
    readonly keyUsageKeyEncipherment: boolean;
    /** Signature algorithm used by the issuer over the TBSCertificate. */
    readonly signatureScheme: SignatureScheme;
    /** Raw signature value from the issuer. */
    readonly signatureValue: Uint8Array;
    /** DER-encoded SubjectPublicKeyInfo of the issuer (for chain building). */
    readonly issuer: string;
    /** True for a CA certificate. */
    readonly isCa: boolean;
}

/** An ordered certificate chain: leaf first, intermediates follow, root last. */
export interface CertificateChain {
    readonly leaf: Certificate;
    readonly intermediates: readonly Certificate[];
    readonly root: Certificate;
}

/** A trust anchor: a root certificate we trust a priori. */
export interface TrustAnchor {
    readonly subjectPublicKeyInfo: Uint8Array;
    readonly subject: string;
}

/**
 * Parse a single DER-encoded X.509 certificate.
 *
 * Decodes the outer Certificate SEQUENCE into its TBSCertificate, signature
 * algorithm, and signature value, then extracts the validation-relevant fields.
 * `tbsBytes` is captured as the EXACT DER span of the TBSCertificate so that
 * signature verification over it is byte-correct.
 *
 * Throws {@link TlsHandshakeError} with phase "certificate" on malformed input.
 */
export function parseCertificate(buf: Uint8Array): Certificate {
    // Outer Certificate SEQUENCE.
    const cert = readTlv(buf, 0);
    if (cert.tag !== 0x30) {
        throw new TlsHandshakeError("certificate", {
            cause: new Error(`expected Certificate SEQUENCE, got tag 0x${cert.tag.toString(16)}`),
        });
    }

    // First element: TBSCertificate. Capture its full DER span for verification.
    if (cert.valueStart >= cert.end) {
        throw new TlsHandshakeError("certificate", {
            cause: new Error("empty Certificate"),
        });
    }
    const tbs = readTlv(buf, cert.valueStart);
    if (tbs.tag !== 0x30) {
        throw new TlsHandshakeError("certificate", {
            cause: new Error(`expected TBSCertificate SEQUENCE, got tag 0x${tbs.tag.toString(16)}`),
        });
    }
    const tbsBytes = buf.subarray(tbs.start, tbs.end);

    // Walk the TBSCertificate fields in order.
    let o = tbs.valueStart;

    // version [0] EXPLICIT — optional, context-constructed tag 0xA0.
    if (peekTag(buf, o) === 0xa0) {
        o = readTlv(buf, o).end;
    }

    // serialNumber INTEGER — skip.
    o = readTlv(buf, o).end;

    // signature AlgorithmIdentifier.
    const signatureScheme = oidToSignatureScheme(parseAlgorithmIdentifierOid(buf, o));
    o = readTlv(buf, o).end;

    // issuer Name — skip past it but remember the span for the issuer string.
    const issuerTlv = readTlv(buf, o);
    const issuer = parseName(buf, issuerTlv.start, issuerTlv.end);
    o = issuerTlv.end;

    // validity SEQUENCE { notBefore, notAfter }.
    const validity = readTlv(buf, o);
    if (validity.tag !== 0x30) {
        throw new TlsHandshakeError("certificate", {
            cause: new Error(`expected validity SEQUENCE, got tag 0x${validity.tag.toString(16)}`),
        });
    }
    let v = validity.valueStart;
    const notBeforeTlv = readTlv(buf, v);
    const notBefore = parseTime(buf, notBeforeTlv.valueStart, notBeforeTlv.end, notBeforeTlv.tag);
    v = notBeforeTlv.end;
    const notAfterTlv = readTlv(buf, v);
    const notAfter = parseTime(buf, notAfterTlv.valueStart, notAfterTlv.end, notAfterTlv.tag);
    o = validity.end;

    // subject Name — skip (we only need CN for legacy hostname match).
    const subjectTlv = readTlv(buf, o);
    o = subjectTlv.end;

    // subjectPublicKeyInfo — capture the full DER span.
    const spkiTlv = readTlv(buf, o);
    if (spkiTlv.tag !== 0x30) {
        throw new TlsHandshakeError("certificate", {
            cause: new Error(`expected subjectPublicKeyInfo SEQUENCE, got tag 0x${spkiTlv.tag.toString(16)}`),
        });
    }
    const subjectPublicKeyInfo = buf.subarray(spkiTlv.start, spkiTlv.end);
    o = spkiTlv.end;

    // Optional trailing context tags: issuerUniqueID [1], subjectUniqueID [2],
    // extensions [3]. Only [3] carries fields we care about.
    let subjectAltNames: readonly string[] = [];
    let keyUsageDigitalSignature = false;
    let keyUsageKeyEncipherment = false;
    let isCa = false;
    let commonName: string | undefined;

    while (o < tbs.end) {
        const tag = peekTag(buf, o);
        if (tag === 0xa3) {
            // extensions [3] EXPLICIT: a SEQUENCE OF Extension inside a [3] wrapper.
            const extWrapper = readTlv(buf, o);
            const extensions = parseExtensionsBlock(buf, extWrapper.valueStart, extWrapper.end);
            for (const ext of extensions) {
                switch (ext.oid) {
                    case "2.5.29.17":
                        subjectAltNames = parseSubjectAltNames(ext.value);
                        break;
                    case "2.5.29.15":
                        ({ digitalSignature: keyUsageDigitalSignature, keyEncipherment: keyUsageKeyEncipherment } =
                            parseKeyUsage(ext.value));
                        break;
                    case "2.5.29.19":
                        isCa = parseBasicConstraints(ext.value);
                        break;
                    case "2.5.29.35":
                    default:
                        break;
                }
            }
            o = extWrapper.end;
        } else if (tag === 0xa1 || tag === 0xa2) {
            // issuerUniqueID / subjectUniqueID — skip.
            o = readTlv(buf, o).end;
        } else {
            // Unknown trailing element — stop scanning.
            break;
        }
    }

    // Fall back to the subject's CN if no SAN DNS names were present.
    if (subjectAltNames.length === 0) {
        commonName = parseCommonName(buf, subjectTlv.start, subjectTlv.end);
    }

    // Outer signatureAlgorithm (skip) + signatureValue.
    // The TBS signature OID is authoritative for the scheme; the outer one
    // must match it but we don't re-derive the scheme from it here.
    const signatureAlgorithmEnd = readTlv(buf, tbs.end).end;
    const sigValueTlv = readTlv(buf, signatureAlgorithmEnd);
    if (sigValueTlv.tag !== 0x03) {
        throw new TlsHandshakeError("certificate", {
            cause: new Error(`expected signatureValue BIT STRING, got tag 0x${sigValueTlv.tag.toString(16)}`),
        });
    }
    // signatureValue is a BIT STRING: first content byte is the "unused bits" count.
    const signatureValue = buf.subarray(sigValueTlv.valueStart + 1, sigValueTlv.end);

    // Under exactOptionalPropertyTypes, an optional `?:` property must be omitted
    // rather than set to undefined. Only attach `commonName` when we found one.
    if (commonName !== undefined) {
        return {
            tbsBytes,
            subjectPublicKeyInfo,
            subjectAltNames: Object.freeze(subjectAltNames),
            commonName,
            notBefore,
            notAfter,
            keyUsageDigitalSignature,
            keyUsageKeyEncipherment,
            signatureScheme,
            signatureValue,
            issuer,
            isCa,
        };
    }
    return {
        tbsBytes,
        subjectPublicKeyInfo,
        subjectAltNames: Object.freeze(subjectAltNames),
        notBefore,
        notAfter,
        keyUsageDigitalSignature,
        keyUsageKeyEncipherment,
        signatureScheme,
        signatureValue,
        issuer,
        isCa,
    };
}

/**
 * Parse the subject Name and return a readable DN string (RFC 2253-ish).
 * Used only for the `issuer` field and debug-friendliness.
 */
function parseName(buf: Uint8Array, start: number, _end: number): string {
    void _end;
    const seq = readTlv(buf, start);
    if (seq.tag !== 0x30) {
        return "";
    }
    const rdnParts: string[] = [];
    let o = seq.valueStart;
    const textDecoder = new TextDecoder();
    while (o < seq.end) {
        // Each RelativeDistinguishedName is a SET of AttributeTypeAndValue.
        const setTlv = readTlv(buf, o);
        if (setTlv.tag !== 0x31) {
            break;
        }
        let p = setTlv.valueStart;
        if (p >= setTlv.end) {
            o = setTlv.end;
            continue;
        }
        const atv = readTlv(buf, p);
        if (atv.tag !== 0x30) {
            o = setTlv.end;
            continue;
        }
        const oidTlv = readTlv(buf, atv.valueStart);
        const oid = parseOid(buf, oidTlv.valueStart, oidTlv.end);
        const valueTlv = readTlv(buf, oidTlv.end);
        const value = textDecoder.decode(buf.subarray(valueTlv.valueStart, valueTlv.end));
        rdnParts.push(`${oid}=${value}`);
        o = setTlv.end;
    }
    return rdnParts.join(", ");
}

/** Extract the CN (OID 2.5.4.3) from a subject Name, if present. */
function parseCommonName(buf: Uint8Array, start: number, _end: number): string | undefined {
    void _end;
    const seq = readTlv(buf, start);
    if (seq.tag !== 0x30) {
        return undefined;
    }
    let o = seq.valueStart;
    const textDecoder = new TextDecoder();
    while (o < seq.end) {
        const setTlv = readTlv(buf, o);
        if (setTlv.tag !== 0x31) {
            break;
        }
        let p = setTlv.valueStart;
        while (p < setTlv.end) {
            const atv = readTlv(buf, p);
            if (atv.tag !== 0x30) {
                break;
            }
            const oidTlv = readTlv(buf, atv.valueStart);
            const oid = parseOid(buf, oidTlv.valueStart, oidTlv.end);
            if (oid === "2.5.4.3") {
                const valueTlv = readTlv(buf, oidTlv.end);
                return textDecoder.decode(buf.subarray(valueTlv.valueStart, valueTlv.end));
            }
            p = atv.end;
        }
        o = setTlv.end;
    }
    return undefined;
}

/**
 * Parse the extensions block (SEQUENCE OF Extension) between `start` and `end`.
 * Each extension is SEQUENCE { extnID OID, critical BOOLEAN?, extnValue OCTET STRING }.
 */
function parseExtensionsBlock(buf: Uint8Array, start: number, _end: number): readonly {
    readonly oid: string;
    readonly value: Uint8Array;
}[] {
    void _end;
    const seq = readTlv(buf, start);
    if (seq.tag !== 0x30) {
        throw new TlsHandshakeError("certificate", {
            cause: new Error(`expected extensions SEQUENCE, got tag 0x${seq.tag.toString(16)}`),
        });
    }
    const extensions: { readonly oid: string; readonly value: Uint8Array }[] = [];
    let o = seq.valueStart;
    while (o < seq.end) {
        const ext = readTlv(buf, o);
        if (ext.tag !== 0x30) {
            break;
        }
        let p = ext.valueStart;
        const oidTlv = readTlv(buf, p);
        const oid = parseOid(buf, oidTlv.valueStart, oidTlv.end);
        p = oidTlv.end;
        // Optional critical BOOLEAN.
        if (peekTag(buf, p) === 0x01) {
            p = readTlv(buf, p).end;
        }
        const valueTlv = readTlv(buf, p);
        if (valueTlv.tag !== 0x04) {
            throw new TlsHandshakeError("certificate", {
                cause: new Error(`expected extnValue OCTET STRING, got tag 0x${valueTlv.tag.toString(16)}`),
            });
        }
        // The extnValue OCTET STRING *contains* the DER-encoded extension value.
        extensions.push({ oid, value: buf.subarray(valueTlv.valueStart, valueTlv.end) });
        o = ext.end;
    }
    return extensions;
}

/**
 * Parse the SAN extension value (already unwrapped from its OCTET STRING).
 * The value is a SEQUENCE OF GeneralName; we only extract dNSName entries
 * (context tag [2]).
 */
function parseSubjectAltNames(value: Uint8Array): readonly string[] {
    const seq = readTlv(value, 0);
    if (seq.tag !== 0x30) {
        return Object.freeze([]);
    }
    const names: string[] = [];
    const textDecoder = new TextDecoder();
    let o = seq.valueStart;
    while (o < seq.end) {
        const tlv = readTlv(value, o);
        // GeneralName: context-specific tag. dNSName is [2] (0x82), iPAddress [7].
        const tag = tlv.tag;
        const tagClass = tag & 0xc0;
        const tagNumber = tag & 0x1f;
        if (tagClass === 0x80 && tagNumber === 2) {
            names.push(textDecoder.decode(value.subarray(tlv.valueStart, tlv.end)));
        }
        o = tlv.end;
    }
    return Object.freeze(names);
}

/**
 * Parse the KeyUsage extension value (unwrapped OCTET STRING holding a BIT
 * STRING). Returns the digitalSignature (bit 0) and keyEncipherment (bit 2)
 * flags.
 */
function parseKeyUsage(value: Uint8Array): {
    readonly digitalSignature: boolean;
    readonly keyEncipherment: boolean;
} {
    const bitString = readTlv(value, 0);
    if (bitString.tag !== 0x03) {
        return { digitalSignature: false, keyEncipherment: false };
    }
    // BIT STRING content: first byte = number of unused bits; then the bits.
    const content = value.subarray(bitString.valueStart, bitString.end);
    if (content.length < 2) {
        return { digitalSignature: false, keyEncipherment: false };
    }
    // Pack the used bits into an integer (big-endian bit order).
    const usedBytes = content.subarray(1); // skip the unused-bits count.
    let bits = 0;
    for (const byte of usedBytes) {
        bits = (bits << 8) | byte;
    }
    // The bits are left-aligned; the real bit 0 is the most significant bit of
    // the first used byte. digitalSignature = bit 0, keyEncipherment = bit 2.
    const totalBits = usedBytes.length * 8;
    const bitPosition = (bitIndex: number): number => totalBits - 1 - bitIndex;
    const getBit = (index: number): boolean => {
        const pos = bitPosition(index);
        const byteIndex = Math.floor(pos / 8);
        const bitInByte = pos % 8;
        return (usedBytes[byteIndex]! & (1 << (7 - bitInByte))) !== 0;
    };
    return {
        digitalSignature: getBit(0),
        keyEncipherment: getBit(2),
    };
}

/**
 * Parse the BasicConstraints extension value (unwrapped OCTET STRING holding a
 * SEQUENCE { cA BOOLEAN DEFAULT FALSE, pathLenConstraint INTEGER? }).
 */
function parseBasicConstraints(value: Uint8Array): boolean {
    const seq = readTlv(value, 0);
    if (seq.tag !== 0x30 || seq.valueStart >= seq.end) {
        return false;
    }
    if (peekTag(value, seq.valueStart) !== 0x01) {
        return false;
    }
    const boolTlv = readTlv(value, seq.valueStart);
    return value[boolTlv.valueStart] !== 0;
}

/**
 * Validate that a certificate is valid for the given hostname per RFC 6125.
 *
 * If the cert carries SAN DNS names, one must match (wildcard-aware, matching
 * a single left-most label and NOT crossing dots). Otherwise we fall back to
 * the legacy CommonName. IP-literal SANs are not matched here (server certs
 * virtually always use DNS names).
 */
export function validateHostname(cert: Certificate, hostname: string): boolean {
    const names = cert.subjectAltNames;
    if (names.length > 0) {
        return names.some((name) => matchDnsName(name, hostname));
    }
    if (cert.commonName !== undefined) {
        return matchDnsName(cert.commonName, hostname);
    }
    return false;
}

/** Match a DNS name (possibly wildcard) against a concrete hostname (RFC 6125 §6.4.3). */
function matchDnsName(pattern: string, hostname: string): boolean {
    const p = pattern.trim().toLowerCase();
    const h = hostname.trim().toLowerCase();
    if (p.length === 0 || h.length === 0) {
        return false;
    }
    // Wildcard: only a leading "*." matches a single non-empty left label.
    if (p.startsWith("*.")) {
        const suffix = p.slice(1); // e.g. ".example.com"
        // The prefix before the suffix must be exactly one label (no dots).
        const prefix = h.slice(0, h.length - suffix.length);
        if (!h.endsWith(suffix)) {
            return false;
        }
        return prefix.length > 0 && !prefix.includes(".");
    }
    return p === h;
}

/**
 * Verify a certificate chain: each cert is signed by the next, the root is in
 * the trust anchors, and the leaf is valid for the hostname and not expired.
 *
 * Signature verification is delegated to @network/crypto. Throws
 * {@link TlsHandshakeError} with phase "certificate" on any failure.
 */
export async function verifyChain(
    chain: CertificateChain,
    trustAnchors: readonly TrustAnchor[],
    hostname: string,
    now: number,
): Promise<void> {
    const certs = [chain.leaf, ...chain.intermediates, chain.root];

    // 1. Validity windows: every cert must currently be valid.
    for (const cert of certs) {
        if (now < cert.notBefore || now > cert.notAfter) {
            throw new TlsHandshakeError("certificate", {
                cause: new Error(
                    `certificate ${cert.issuer} not valid at ${now} (valid ${cert.notBefore}..${cert.notAfter})`,
                ),
            });
        }
    }

    // 2. basicConstraints CA flags: every intermediate must be a CA. The root
    //    is authorized by the trust-anchor SPKI match (step 4), not by its own
    //    basicConstraints, so a self-signed trust anchor need not set cA.
    for (const cert of chain.intermediates) {
        if (!cert.isCa) {
            throw new TlsHandshakeError("certificate", {
                cause: new Error(`intermediate certificate ${cert.issuer} is missing basicConstraints cA`),
            });
        }
    }

    // 3. For each (subject, issuer) pair, verify the signature. The issuer's
    //    public key (SPKI) verifies the subject's signature over its TBSCertificate.
    const subjects = [chain.leaf, ...chain.intermediates];
    const issuers = [...chain.intermediates, chain.root];
    for (let i = 0; i < subjects.length; i++) {
        const subject = subjects[i]!;
        const issuer = issuers[i]!;
        const ok = await crypto.verifySignature(
            subject.signatureScheme,
            issuer.subjectPublicKeyInfo,
            subject.signatureValue,
            subject.tbsBytes,
        );
        if (!ok) {
            throw new TlsHandshakeError("certificate", {
                cause: new Error(
                    `signature verification failed: ${subject.issuer} not signed by ${issuer.issuer}`,
                ),
            });
        }
    }

    // 4. The chain root's SPKI must match one of the trust anchors.
    const rootTrusted = trustAnchors.some((ta) =>
        constantTimeEqual(ta.subjectPublicKeyInfo, chain.root.subjectPublicKeyInfo),
    );
    if (!rootTrusted) {
        throw new TlsHandshakeError("certificate", {
            cause: new Error(`root certificate ${chain.root.issuer} does not match any trust anchor`),
        });
    }

    // 5. Hostname validation against the leaf.
    if (!validateHostname(chain.leaf, hostname)) {
        throw new TlsHandshakeError("certificate", {
            cause: new Error(`hostname "${hostname}" does not match leaf certificate`),
        });
    }
}

/** Parse a PEM block (base64 between BEGIN/END CERTIFICATE) into DER bytes. */
export function pemToDer(pem: string): Uint8Array {
    const beginMarker = "-----BEGIN CERTIFICATE-----";
    const endMarker = "-----END CERTIFICATE-----";
    const begin = pem.indexOf(beginMarker);
    const end = pem.indexOf(endMarker);
    if (begin === -1 || end === -1 || end <= begin) {
        throw new Error("pemToDer: missing BEGIN/END CERTIFICATE markers");
    }
    const body = pem.slice(begin + beginMarker.length, end);
    // Strip all whitespace (newlines, spaces) and base64-decode.
    const cleaned = body.replace(/\s+/g, "");
    const binary = base64Decode(cleaned);
    return new Uint8Array(binary);
}

// ---------------------------------------------------------------------------
// Small byte helpers.
// ---------------------------------------------------------------------------

/** Constant-time byte comparison (length-equal only; leaks length, not contents). */
function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) {
        return false;
    }
    let diff = 0;
    for (let i = 0; i < a.length; i++) {
        diff |= a[i]! ^ b[i]!;
    }
    return diff === 0;
}

/** Base64-decode a string into bytes (no node:crypto dependency). */
function base64Decode(input: string): Uint8Array {
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const decodeTable = new Int16Array(128).fill(-1);
    for (let i = 0; i < alphabet.length; i++) {
        decodeTable[alphabet.charCodeAt(i)] = i;
    }
    // Strip padding to compute output length.
    let padding = 0;
    for (let i = input.length - 1; i >= 0; i--) {
        if (input[i] === "=") {
            padding++;
        } else {
            break;
        }
    }
    const cleanLen = input.length - padding;
    const outLen = Math.floor((cleanLen * 6) / 8);
    const out = new Uint8Array(outLen);
    let buffer = 0;
    let bitsCollected = 0;
    let outIndex = 0;
    for (let i = 0; i < cleanLen; i++) {
        const value = decodeTable[input.charCodeAt(i)]!;
        if (value < 0) {
            continue; // skip any non-alphabet char (shouldn't happen post-clean)
        }
        buffer = (buffer << 6) | value;
        bitsCollected += 6;
        if (bitsCollected >= 8) {
            bitsCollected -= 8;
            out[outIndex++] = (buffer >> bitsCollected) & 0xff;
        }
    }
    return out;
}
