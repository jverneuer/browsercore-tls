/**
 * X.509 name and extension parsing.
 *
 * These decode the higher-level X.509 structures a TLS server cert actually
 * carries: the subject/issuer DistinguishedNames (RFC 2253), the SAN
 * extension (the source of truth for hostname validation), KeyUsage, and
 * BasicConstraints (the cA flag that separates leaf from CA certs). They sit on
 * top of the raw DER primitives in `der.ts` but are agnostic to validation
 * policy — they only turn bytes into structured fields.
 */

import { readTlv, peekTag, parseOid } from "./der.js";
import { TlsHandshakeError } from "../errors.js";

/**
 * Parse the subject Name and return a readable DN string (RFC 2253-ish).
 * Used only for the `issuer` field and debug-friendliness.
 */
export function parseName(buf: Uint8Array, start: number, _end: number): string {
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
        const p = setTlv.valueStart;
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
export function parseCommonName(buf: Uint8Array, start: number, _end: number): string | undefined {
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
export function parseExtensionsBlock(buf: Uint8Array, start: number, _end: number): readonly {
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
export function parseSubjectAltNames(value: Uint8Array): readonly string[] {
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
export function parseKeyUsage(value: Uint8Array): {
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
    // bitIndex therefore maps directly to a big-endian bit position (0 = MSB of
    // the first byte), so no reversal is applied.
    const getBit = (index: number): boolean => {
        const byteIndex = Math.floor(index / 8);
        const bitInByte = index % 8;
        const byte = usedBytes[byteIndex];
        if (byte === undefined) {
            return false;
        }
        return (byte & (1 << (7 - bitInByte))) !== 0;
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
export function parseBasicConstraints(value: Uint8Array): boolean {
    const seq = readTlv(value, 0);
    if (seq.tag !== 0x30 || seq.valueStart >= seq.end) {
        return false;
    }
    if (peekTag(value, seq.valueStart) !== 0x01) {
        return false;
    }
    const boolTlv = readTlv(value, seq.valueStart);
    const boolByte = value[boolTlv.valueStart];
    return boolByte !== undefined && boolByte !== 0;
}
