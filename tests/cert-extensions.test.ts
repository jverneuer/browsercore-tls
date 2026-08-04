/**
 * Direct tests for @browsercore/tls X.509 name + extension parsing
 * (src/certificates/cert-extensions.ts).
 *
 * These helpers (parseName, parseCommonName, parseExtensionsBlock,
 * parseSubjectAltNames, parseKeyUsage, parseBasicConstraints) are exercised
 * indirectly by certificates.test.ts and certificates.parse.test.ts through
 * parseCertificate, but several branches are only reachable by feeding the
 * functions crafted DER directly. This file drives every branch that the
 * indirect path misses — the early returns, the lenient skips, and the
 * bit-level decoders — so the parser's real behaviour is pinned rather than
 * inferred from the top-level parse.
 */

import { describe, it, expect } from "vitest";
import {
    parseName,
    parseCommonName,
    parseExtensionsBlock,
    parseSubjectAltNames,
    parseKeyUsage,
    parseBasicConstraints,
} from "../src/certificates/cert-extensions.js";
import { TlsHandshakeError } from "../src/errors.js";

// ---------------------------------------------------------------------------
// Minimal ASN.1 encoding helpers (test-only). Kept local so this file is
// self-contained.
// ---------------------------------------------------------------------------

function concatBytes(...chunks: Uint8Array[]): Uint8Array {
    const total = chunks.reduce((sum, c) => sum + c.length, 0);
    const out = new Uint8Array(total);
    let o = 0;
    for (const c of chunks) {
        out.set(c, o);
        o += c.length;
    }
    return out;
}

function encodeLength(length: number): Uint8Array {
    if (length < 0x80) {
        return new Uint8Array([length]);
    }
    const bytes: number[] = [];
    let remaining = length;
    while (remaining > 0) {
        bytes.unshift(remaining & 0xff);
        remaining >>= 8;
    }
    return new Uint8Array([0x80 | bytes.length, ...bytes]);
}

function wrapTag(tag: number, content: Uint8Array): Uint8Array {
    return concatBytes(new Uint8Array([tag]), encodeLength(content.length), content);
}

function wrapSequence(content: Uint8Array): Uint8Array {
    return wrapTag(0x30, content);
}

function wrapOid(oid: string): Uint8Array {
    const parts = oid.split(".").map((p) => Number.parseInt(p, 10));
    const first = parts[0]! * 40 + parts[1]!;
    const rest: number[] = [];
    for (const arc of parts.slice(2)) {
        if (arc === 0) {
            rest.push(0);
            continue;
        }
        const bytes: number[] = [];
        let value = arc;
        while (value > 0) {
            bytes.unshift((value & 0x7f) | (bytes.length === 0 ? 0 : 0x80));
            value >>= 7;
        }
        rest.push(...bytes);
    }
    return wrapTag(0x06, new Uint8Array([first, ...rest]));
}

function wrapUtf8String(value: Uint8Array): Uint8Array {
    return wrapTag(0x0c, value);
}

function wrapSetOf(...parts: Uint8Array[]): Uint8Array {
    return wrapTag(0x31, concatBytes(...parts));
}

// ---------------------------------------------------------------------------
// parseName
// ---------------------------------------------------------------------------

describe("parseName", () => {
    function encodeName(commonName: string): Uint8Array {
        const cnValue = wrapUtf8String(new TextEncoder().encode(commonName));
        const atv = wrapSequence(concatBytes(wrapOid("2.5.4.3"), cnValue));
        const rdn = wrapSetOf(atv);
        return wrapSequence(concatBytes(rdn));
    }

    it("returns an empty string when the input is not a SEQUENCE", () => {
        // A SET (0x31) instead of a SEQUENCE (0x30) — parseName bails early.
        const notASequence = wrapTag(0x31, new Uint8Array(0));
        expect(parseName(notASequence, 0, notASequence.length)).toBe("");
    });

    it("formats a single-attribute Name as `2.5.4.3=<cn>`", () => {
        const name = encodeName("example.com");
        expect(parseName(name, 0, name.length)).toBe("2.5.4.3=example.com");
    });

    it("joins multiple RDN parts with commas", () => {
        const cnValue = wrapUtf8String(new TextEncoder().encode("example.com"));
        const cnAtv = wrapSequence(concatBytes(wrapOid("2.5.4.3"), cnValue));
        const cnRdn = wrapSetOf(cnAtv);
        // OID 2.5.4.10 = organizationName.
        const orgValue = wrapUtf8String(new TextEncoder().encode("ACME"));
        const orgAtv = wrapSequence(concatBytes(wrapOid("2.5.4.10"), orgValue));
        const orgRdn = wrapSetOf(orgAtv);
        const name = wrapSequence(concatBytes(cnRdn, orgRdn));
        const parsed = parseName(name, 0, name.length);
        expect(parsed).toContain("2.5.4.3=example.com");
        expect(parsed).toContain("2.5.4.10=ACME");
    });

    it("breaks out of the loop on a malformed RDN (not a SET)", () => {
        // SEQUENCE { INTEGER } — the lone element is not a SET (0x31), so the
        // RDN loop breaks and the (empty) accumulator is returned.
        const bad = wrapSequence(wrapTag(0x02, new Uint8Array([0x01])));
        expect(parseName(bad, 0, bad.length)).toBe("");
    });

    it("skips an AttributeTypeAndValue that is not a SEQUENCE", () => {
        // SET { INTEGER } — the ATV inside the SET is not a SEQUENCE, so the
        // inner `continue` fires and the RDN contributes no part.
        const badAtv = wrapSetOf(wrapTag(0x02, new Uint8Array([0x01])));
        const name = wrapSequence(concatBytes(badAtv));
        expect(parseName(name, 0, name.length)).toBe("");
    });
});

// ---------------------------------------------------------------------------
// parseCommonName
// ---------------------------------------------------------------------------

describe("parseCommonName", () => {
    function encodeNameWithCn(cn: string): Uint8Array {
        const cnValue = wrapUtf8String(new TextEncoder().encode(cn));
        const atv = wrapSequence(concatBytes(wrapOid("2.5.4.3"), cnValue));
        const rdn = wrapSetOf(atv);
        return wrapSequence(concatBytes(rdn));
    }

    it("returns undefined when the input is not a SEQUENCE", () => {
        const notASequence = wrapTag(0x31, new Uint8Array(0));
        expect(parseCommonName(notASequence, 0, notASequence.length)).toBeUndefined();
    });

    it("returns undefined when no RDN carries OID 2.5.4.3", () => {
        // An organizationName (2.5.4.10) but no commonName.
        const orgValue = wrapUtf8String(new TextEncoder().encode("ACME"));
        const atv = wrapSequence(concatBytes(wrapOid("2.5.4.10"), orgValue));
        const rdn = wrapSetOf(atv);
        const name = wrapSequence(concatBytes(rdn));
        expect(parseCommonName(name, 0, name.length)).toBeUndefined();
    });

    it("extracts the CN from a well-formed Name", () => {
        const name = encodeNameWithCn("legacy.example.org");
        expect(parseCommonName(name, 0, name.length)).toBe("legacy.example.org");
    });
});

// ---------------------------------------------------------------------------
// parseExtensionsBlock
// ---------------------------------------------------------------------------

describe("parseExtensionsBlock", () => {
    /** Encode one Extension { OID, critical BOOLEAN TRUE, OCTET STRING{value} }. */
    function extWith(oid: string, value: Uint8Array, critical = false): Uint8Array {
        const body = critical
            ? concatBytes(wrapOid(oid), wrapTag(0x01, new Uint8Array([0xff])), wrapTag(0x04, value))
            : concatBytes(wrapOid(oid), wrapTag(0x04, value));
        return wrapSequence(body);
    }

    it("throws when the block is not a SEQUENCE", () => {
        const bad = wrapTag(0x31, new Uint8Array(0)); // SET, not SEQUENCE
        expect(() => parseExtensionsBlock(bad, 0, bad.length)).toThrow(TlsHandshakeError);
    });

    it("parses a block with a single extension", () => {
        const block = wrapSequence(extWith("2.5.29.17", new Uint8Array([0x01])));
        const extensions = parseExtensionsBlock(block, 0, block.length);
        expect(extensions).toHaveLength(1);
        expect(extensions[0]!.oid).toBe("2.5.29.17");
        expect(extensions[0]!.value).toEqual(new Uint8Array([0x01]));
    });

    it("parses an extension carrying the critical BOOLEAN", () => {
        const block = wrapSequence(extWith("2.5.29.19", new Uint8Array([0xff]), true));
        const extensions = parseExtensionsBlock(block, 0, block.length);
        expect(extensions).toHaveLength(1);
        expect(extensions[0]!.oid).toBe("2.5.29.19");
    });

    it("stops scanning at an entry that is not a SEQUENCE", () => {
        // SEQUENCE OF { INTEGER } — the lone entry is not an Extension SEQUENCE,
        // so the block yields zero extensions rather than throwing.
        const block = wrapSequence(wrapTag(0x02, new Uint8Array([0x01])));
        const extensions = parseExtensionsBlock(block, 0, block.length);
        expect(extensions).toEqual([]);
    });

    it("throws when the extnValue is not an OCTET STRING", () => {
        // Extension { OID, INTEGER(instead of OCTET STRING) }
        const ext = wrapSequence(concatBytes(wrapOid("2.5.29.17"), wrapTag(0x02, new Uint8Array([0x00]))));
        const block = wrapSequence(ext);
        expect(() => parseExtensionsBlock(block, 0, block.length)).toThrow(/expected extnValue OCTET STRING/);
    });
});

// ---------------------------------------------------------------------------
// parseSubjectAltNames
// ---------------------------------------------------------------------------

describe("parseSubjectAltNames", () => {
    it("returns an empty array when the value is not a SEQUENCE", () => {
        // An INTEGER instead of a SEQUENCE OF GeneralName.
        const bad = wrapTag(0x02, new Uint8Array([0x00]));
        expect(parseSubjectAltNames(bad)).toEqual([]);
    });

    it("extracts a single dNSName (context tag [2])", () => {
        const dns = wrapTag(0x82, new TextEncoder().encode("example.com"));
        const san = wrapSequence(dns);
        expect(parseSubjectAltNames(san)).toEqual(["example.com"]);
    });

    it("extracts multiple dNSNames in order", () => {
        const a = wrapTag(0x82, new TextEncoder().encode("a.example.com"));
        const b = wrapTag(0x82, new TextEncoder().encode("b.example.com"));
        const san = wrapSequence(concatBytes(a, b));
        expect(parseSubjectAltNames(san)).toEqual(["a.example.com", "b.example.com"]);
    });

    it("skips non-DNS GeneralNames (e.g. iPAddress tag [7])", () => {
        const ip = wrapTag(0x87, new Uint8Array([127, 0, 0, 1]));
        const dns = wrapTag(0x82, new TextEncoder().encode("example.com"));
        const san = wrapSequence(concatBytes(ip, dns));
        expect(parseSubjectAltNames(san)).toEqual(["example.com"]);
    });
});

// ---------------------------------------------------------------------------
// parseKeyUsage
// ---------------------------------------------------------------------------

describe("parseKeyUsage", () => {
    it("returns both flags false when the value is not a BIT STRING", () => {
        // An INTEGER instead of a BIT STRING (0x03).
        const bad = wrapTag(0x02, new Uint8Array([0x00]));
        expect(parseKeyUsage(bad)).toEqual({ digitalSignature: false, keyEncipherment: false });
    });

    it("returns both flags false when the BIT STRING content is too short", () => {
        // BIT STRING with only the unused-bits byte (content.length < 2).
        const inner = wrapTag(0x03, new Uint8Array([0x00]));
        expect(parseKeyUsage(inner)).toEqual({ digitalSignature: false, keyEncipherment: false });
    });

    it("decodes digitalSignature (bit 0) and keyEncipherment (bit 2)", () => {
        // KeyUsage BIT STRING: unused-bits=0, then a single byte.
        //   bit 0 = digitalSignature, bit 2 = keyEncipherment.
        // To set bit 0 only: byte = 0b1000_0000 (the MSB is bit 0).
        const onlySig = wrapTag(0x03, new Uint8Array([0x00, 0b1000_0000]));
        expect(parseKeyUsage(onlySig)).toEqual({ digitalSignature: true, keyEncipherment: false });

        // To set bit 2 only: byte = 0b0010_0000 (bit 2 from the left).
        const onlyEnc = wrapTag(0x03, new Uint8Array([0x00, 0b0010_0000]));
        expect(parseKeyUsage(onlyEnc)).toEqual({ digitalSignature: false, keyEncipherment: true });

        // Both bits set.
        const both = wrapTag(0x03, new Uint8Array([0x00, 0b1010_0000]));
        expect(parseKeyUsage(both)).toEqual({ digitalSignature: true, keyEncipherment: true });
    });
});

// ---------------------------------------------------------------------------
// parseBasicConstraints
// ---------------------------------------------------------------------------

describe("parseBasicConstraints", () => {
    it("returns false when the value is not a SEQUENCE", () => {
        const bad = wrapTag(0x02, new Uint8Array([0x00]));
        expect(parseBasicConstraints(bad)).toBe(false);
    });

    it("returns false for an empty SEQUENCE", () => {
        const empty = wrapSequence(new Uint8Array(0));
        expect(parseBasicConstraints(empty)).toBe(false);
    });

    it("returns false when the SEQUENCE does not start with a BOOLEAN", () => {
        // SEQUENCE { INTEGER } — no BOOLEAN at value start.
        const noBool = wrapSequence(wrapTag(0x02, new Uint8Array([0x00])));
        expect(parseBasicConstraints(noBool)).toBe(false);
    });

    it("returns false for cA = FALSE (0x00)", () => {
        const inner = wrapSequence(wrapTag(0x01, new Uint8Array([0x00])));
        expect(parseBasicConstraints(inner)).toBe(false);
    });

    it("returns true for cA = TRUE (any non-zero byte)", () => {
        const inner = wrapSequence(wrapTag(0x01, new Uint8Array([0xff])));
        expect(parseBasicConstraints(inner)).toBe(true);
    });
});
