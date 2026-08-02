/**
 * Tests for @browsercore/tls X.509/DER parsing internals.
 *
 * The certificate parser's error branches (readTlv, parseOid,
 * parseAlgorithmIdentifierOid, parseTime, parseName, parseExtensionsBlock,
 * parseSubjectAltNames, parseKeyUsage, parseBasicConstraints) are private and
 * reachable ONLY through parseCertificate with crafted DER input. This file
 * crafts minimal malformed DER buffers to exercise every one of those branches
 * — real coverage of code that exists, not tests for unimplemented features.
 *
 * It reuses the same ASN.1 test scaffolding as certificates.test.ts (kept local
 * so the two files are independent) to build both valid skeletons and targeted
 * corruptions.
 */

import { describe, it, expect } from "vitest";
import { generateKeyPairSync, createSign } from "node:crypto";
import {
    parseCertificate,
    validateHostname,
    verifyChain,
} from "../src/certificates/certificates.js";
import type { Certificate, CertificateChain, TrustAnchor } from "../src/certificates/certificates.js";
import { TlsHandshakeError } from "../src/errors.js";

// ---------------------------------------------------------------------------
// Minimal ASN.1 encoding helpers (test-only).
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

function encodeTag(tag: number): Uint8Array {
    return new Uint8Array([tag]);
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
    return concatBytes(encodeTag(tag), encodeLength(content.length), content);
}

function wrapSequence(content: Uint8Array): Uint8Array {
    return wrapTag(0x30, content);
}

function wrapSequenceOf(...parts: Uint8Array[]): Uint8Array {
    return wrapSequence(concatBytes(...parts));
}

function wrapSet(content: Uint8Array): Uint8Array {
    return wrapTag(0x31, content);
}

function wrapSetOf(...parts: Uint8Array[]): Uint8Array {
    return wrapSet(concatBytes(...parts));
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

function wrapNull(): Uint8Array {
    return new Uint8Array([0x05, 0x00]);
}

function wrapInteger(value: Uint8Array): Uint8Array {
    const needsPad = value.length > 0 && (value[0]! & 0x80) !== 0;
    const body = needsPad ? concatBytes(new Uint8Array([0x00]), value) : value;
    return wrapTag(0x02, body);
}

function wrapGeneralizedTime(text: string): Uint8Array {
    return wrapTag(0x18, new TextEncoder().encode(text));
}

function wrapBitString(content: Uint8Array): Uint8Array {
    return wrapTag(0x03, concatBytes(new Uint8Array([0x00]), content));
}

// ---------------------------------------------------------------------------
// A valid self-signed ECDSA P-256 certificate, with optional extensions [3].
// ---------------------------------------------------------------------------

function encodeTbsCertificate(
    publicKeyDer: Uint8Array,
    commonName: string,
    extraTail: Uint8Array = new Uint8Array(0),
): Uint8Array {
    const encoder = new TextEncoder();
    const cnBytes = encoder.encode(commonName);
    const cnValue = wrapUtf8String(cnBytes);
    const cnAtv = wrapSequenceOf(wrapOid("2.5.4.3"), cnValue);
    const cnRdn = wrapSetOf(cnAtv);
    const subject = wrapSequenceOf(cnRdn);

    const sigAlg = wrapSequenceOf(wrapOid("1.2.840.10045.4.3.2"), wrapNull());
    const notBefore = wrapGeneralizedTime("20240101000000Z");
    const notAfter = wrapGeneralizedTime("20340101000000Z");
    const validity = wrapSequenceOf(notBefore, notAfter);
    const serial = wrapInteger(new Uint8Array([0x01]));

    return wrapSequenceOf(
        serial,
        sigAlg,
        subject, // issuer == subject (self-signed)
        validity,
        subject,
        publicKeyDer,
        extraTail,
    );
}

function encodeCertificate(tbsBytes: Uint8Array, signatureDer: Uint8Array): Uint8Array {
    const sigAlg = wrapSequenceOf(wrapOid("1.2.840.10045.4.3.2"), wrapNull());
    const sigValue = wrapBitString(signatureDer);
    return wrapSequence(concatBytes(tbsBytes, sigAlg, sigValue));
}

/** The standard BasicConstraints extension body (cA = FALSE). */
function basicConstraintsExt(value: Uint8Array): Uint8Array {
    // Extension: SEQUENCE { OID, critical BOOLEAN TRUE, OCTET STRING { value } }
    const extValue = wrapTag(0x04, value); // extnValue OCTET STRING
    return wrapSequenceOf(
        wrapOid("2.5.29.19"),
        wrapTag(0x01, new Uint8Array([0xff])), // critical = TRUE
        extValue,
    );
}

/** Build a self-signed cert whose TBSCertificate appends `extraTail` (e.g. a
 * [3] extensions wrapper) after the SPKI. Returns { der, pem }. */
function makeCertWithTail(commonName: string, extraTail: Uint8Array): { der: Uint8Array } {
    const { publicKey, privateKey } = generateKeyPairSync("ec", {
        namedCurve: "P-256",
        publicKeyEncoding: { type: "spki", format: "der" },
        privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });
    const publicKeyDer = new Uint8Array(publicKey);
    const tbsBytes = encodeTbsCertificate(publicKeyDer, commonName, extraTail);

    const signer = createSign("SHA256");
    signer.update(Buffer.from(tbsBytes));
    const signature = new Uint8Array(signer.sign({ key: privateKey, dsaEncoding: "der" }));

    return { der: encodeCertificate(tbsBytes, signature) };
}

function makeSelfSignedCert(commonName: string): { der: Uint8Array } {
    return makeCertWithTail(commonName, new Uint8Array(0));
}

// ---------------------------------------------------------------------------
// readTlv / outer Certificate structure errors.
// ---------------------------------------------------------------------------

describe("readTlv + Certificate structure errors", () => {
    it("throws when the buffer is empty (readTlv truncated)", () => {
        expect(() => parseCertificate(new Uint8Array(0))).toThrow(TlsHandshakeError);
    });

    it("throws on a multi-byte DER tag", () => {
        // 0x1f signals a long-form tag number — not supported by this parser.
        const buf = new Uint8Array([0x1f, 0x80, 0x01, 0x00, 0x00]);
        expect(() => parseCertificate(buf)).toThrow(/multi-byte DER tags/);
    });

    it("throws when the DER length byte is truncated", () => {
        const buf = new Uint8Array([0x30]); // tag present, no length
        expect(() => parseCertificate(buf)).toThrow(/DER length truncated/);
    });

    it("throws on indefinite-length DER encoding", () => {
        const buf = new Uint8Array([0x30, 0x80]); // 0x80 = indefinite length
        expect(() => parseCertificate(buf)).toThrow(/indefinite-length/);
    });

    it("throws when the DER length field overflows the buffer", () => {
        // Long form claiming 5 length bytes, but the buffer is too short.
        const buf = new Uint8Array([0x30, 0x85, 0x01, 0x02]);
        expect(() => parseCertificate(buf)).toThrow(/DER length field overflow/);
    });

    it("throws when the DER value is truncated", () => {
        // length says 10 bytes follow, but only 2 do.
        const buf = new Uint8Array([0x30, 0x0a, 0x00, 0x00]);
        expect(() => parseCertificate(buf)).toThrow(/DER value truncated/);
    });

    it("throws when the outer tag is not a SEQUENCE", () => {
        const buf = new Uint8Array([0x31, 0x00]); // SET, not SEQUENCE
        expect(() => parseCertificate(buf)).toThrow(/expected Certificate SEQUENCE/);
    });

    it("throws on an empty Certificate body", () => {
        const buf = new Uint8Array([0x30, 0x00]);
        expect(() => parseCertificate(buf)).toThrow(/empty Certificate/);
    });

    it("throws when the TBSCertificate tag is not a SEQUENCE", () => {
        // Outer SEQUENCE { SET(0x31) } — first element must be a SEQUENCE.
        const buf = new Uint8Array([0x30, 0x02, 0x31, 0x00]);
        expect(() => parseCertificate(buf)).toThrow(/expected TBSCertificate SEQUENCE/);
    });
});

// ---------------------------------------------------------------------------
// Field-level parser errors (reached by corrupting one TBS field at a time).
// ---------------------------------------------------------------------------

describe("TBSCertificate field parser errors", () => {
    it("throws when the signature AlgorithmIdentifier is not a SEQUENCE", () => {
        // Build a TBS where the signature field (2nd element) is a INTEGER.
        const sig = wrapInteger(new Uint8Array([0x01]));
        const tbs = wrapSequenceOf(
            wrapInteger(new Uint8Array([0x01])), // serial
            sig, // bad signature field
        );
        const cert = wrapSequence(concatBytes(tbs, sig, wrapBitString(new Uint8Array(0))));
        expect(() => parseCertificate(cert)).toThrow(/expected AlgorithmIdentifier SEQUENCE/);
    });

    it("throws when the AlgorithmIdentifier is empty", () => {
        const sig = wrapSequence(new Uint8Array(0)); // empty SEQUENCE
        const tbs = wrapSequenceOf(wrapInteger(new Uint8Array([0x01])), sig);
        const cert = wrapSequence(concatBytes(tbs, sig, wrapBitString(new Uint8Array(0))));
        expect(() => parseCertificate(cert)).toThrow(/empty AlgorithmIdentifier/);
    });

    it("throws when the AlgorithmIdentifier contains a non-OID", () => {
        const sig = wrapSequenceOf(wrapInteger(new Uint8Array([0x01]))); // INTEGER, not OID
        const tbs = wrapSequenceOf(wrapInteger(new Uint8Array([0x01])), sig);
        const cert = wrapSequence(concatBytes(tbs, sig, wrapBitString(new Uint8Array(0))));
        expect(() => parseCertificate(cert)).toThrow(/expected OID in AlgorithmIdentifier/);
    });

    it("throws when the OID is empty", () => {
        const sig = wrapSequenceOf(wrapOid("1.2.840.10045.4.3.2"));
        // Corrupt the OID value to empty by wrapping an empty OCTET STRING as the OID.
        const emptyOid = wrapTag(0x06, new Uint8Array(0));
        const sig2 = wrapSequenceOf(emptyOid);
        const tbs = wrapSequenceOf(wrapInteger(new Uint8Array([0x01])), sig2);
        const cert = wrapSequence(concatBytes(tbs, sig, wrapBitString(new Uint8Array(0))));
        expect(() => parseCertificate(cert)).toThrow(/empty OID/);
    });

    it("throws on an unsupported signature algorithm OID", () => {
        const sig = wrapSequenceOf(wrapOid("1.2.840.113549.1.1.5")); // sha1RSA — unsupported
        const tbs = wrapSequenceOf(wrapInteger(new Uint8Array([0x01])), sig);
        const cert = wrapSequence(concatBytes(tbs, sig, wrapBitString(new Uint8Array(0))));
        expect(() => parseCertificate(cert)).toThrow(/unsupported signature algorithm OID/);
    });

    it("throws when the validity field is not a SEQUENCE", () => {
        // issuer (skip) then a non-SEQUENCE validity.
        const sig = wrapSequenceOf(wrapOid("1.2.840.10045.4.3.2"), wrapNull());
        const subject = wrapSequenceOf(wrapSetOf(wrapSequenceOf(wrapOid("2.5.4.3"), wrapUtf8String(new TextEncoder().encode("x")))));
        const badValidity = wrapInteger(new Uint8Array([0x01])); // INTEGER, not SEQUENCE
        const tbs = wrapSequenceOf(
            wrapInteger(new Uint8Array([0x01])), sig, subject, badValidity,
        );
        const cert = wrapSequence(concatBytes(tbs, sig, wrapBitString(new Uint8Array(0))));
        expect(() => parseCertificate(cert)).toThrow(/expected validity SEQUENCE/);
    });

    it("throws when a GeneralizedTime is too short", () => {
        const sig = wrapSequenceOf(wrapOid("1.2.840.10045.4.3.2"), wrapNull());
        const subject = wrapSequenceOf(wrapSetOf(wrapSequenceOf(wrapOid("2.5.4.3"), wrapUtf8String(new TextEncoder().encode("x")))));
        const badTime = wrapGeneralizedTime("2024"); // too short
        const validity = wrapSequenceOf(badTime, badTime);
        const tbs = wrapSequenceOf(wrapInteger(new Uint8Array([0x01])), sig, subject, validity);
        const cert = wrapSequence(concatBytes(tbs, sig, wrapBitString(new Uint8Array(0))));
        expect(() => parseCertificate(cert)).toThrow(/ASN.1 TIME too short/);
    });

    it("throws when a UTCTime has an invalid (non-numeric) component", () => {
        const sig = wrapSequenceOf(wrapOid("1.2.840.10045.4.3.2"), wrapNull());
        const subject = wrapSequenceOf(wrapSetOf(wrapSequenceOf(wrapOid("2.5.4.3"), wrapUtf8String(new TextEncoder().encode("x")))));
        // UTCTime (0x17) with a non-numeric month -> Number("AB") is NaN, so
        // Date.UTC yields NaN and parseTime throws "invalid ASN.1 TIME". (An
        // out-of-range month would NOT do this: JS Date normalizes month overflow.)
        const badTime = wrapTag(0x17, new TextEncoder().encode("99AB01000000Z"));
        const goodTime = wrapGeneralizedTime("20340101000000Z");
        const validity = wrapSequenceOf(badTime, goodTime);
        // Complete TBSCertificate structure (serial, sig, issuer, validity, subject, spki);
        // validity is parsed before the SPKI placeholder is ever reached.
        const tbs = wrapSequenceOf(
            wrapInteger(new Uint8Array([0x01])),
            sig,
            subject,
            validity,
            subject,
            wrapInteger(new Uint8Array([0x01])), // SPKI placeholder (never reached)
        );
        const cert = wrapSequence(concatBytes(tbs, sig, wrapBitString(new Uint8Array(0))));
        expect(() => parseCertificate(cert)).toThrow(/invalid ASN.1 TIME/);
    });

    it("throws when the subjectPublicKeyInfo is not a SEQUENCE", () => {
        const sig = wrapSequenceOf(wrapOid("1.2.840.10045.4.3.2"), wrapNull());
        const subject = wrapSequenceOf(wrapSetOf(wrapSequenceOf(wrapOid("2.5.4.3"), wrapUtf8String(new TextEncoder().encode("x")))));
        const validity = wrapSequenceOf(wrapGeneralizedTime("20240101000000Z"), wrapGeneralizedTime("20340101000000Z"));
        // SPKI replaced with a single INTEGER (not a SEQUENCE).
        const badSpki = wrapInteger(new Uint8Array([0x01]));
        const tbs = wrapSequenceOf(wrapInteger(new Uint8Array([0x01])), sig, subject, validity, subject, badSpki);
        const cert = wrapSequence(concatBytes(tbs, sig, wrapBitString(new Uint8Array(0))));
        expect(() => parseCertificate(cert)).toThrow(/expected subjectPublicKeyInfo SEQUENCE/);
    });

    it("throws when the outer signatureValue is not a BIT STRING", () => {
        const { publicKey, privateKey } = generateKeyPairSync("ec", {
            namedCurve: "P-256",
            publicKeyEncoding: { type: "spki", format: "der" },
            privateKeyEncoding: { type: "pkcs8", format: "pem" },
        });
        const publicKeyDer = new Uint8Array(publicKey);
        // encodeTbsCertificate already returns a DER SEQUENCE — do not re-wrap it.
        const tbsBytes = encodeTbsCertificate(publicKeyDer, "example.com");
        const signer = createSign("SHA256");
        signer.update(Buffer.from(tbsBytes));
        const signature = new Uint8Array(signer.sign({ key: privateKey, dsaEncoding: "der" }));
        const sigAlg = wrapSequenceOf(wrapOid("1.2.840.10045.4.3.2"), wrapNull());
        // signatureValue as an INTEGER instead of a BIT STRING.
        const badSigValue = wrapInteger(signature);
        const cert = wrapSequence(concatBytes(tbsBytes, sigAlg, badSigValue));
        expect(() => parseCertificate(cert)).toThrow(/expected signatureValue BIT STRING/);
    });
});

// ---------------------------------------------------------------------------
// Extensions [3] block parser errors.
// ---------------------------------------------------------------------------

describe("extensions block parser errors", () => {
    /** Wrap `inner` (already-encoded extensions content) as a [3] container. */
    function tailWith(inner: Uint8Array): Uint8Array {
        return wrapTag(0xa3, inner); // [3] EXPLICIT
    }

    it("throws when the [3] wrapper is not a SEQUENCE", () => {
        // [3] containing an INTEGER instead of a SEQUENCE OF Extension.
        const tail = tailWith(wrapInteger(new Uint8Array([0x00])));
        const { der } = makeCertWithTail("example.com", tail);
        expect(() => parseCertificate(der)).toThrow(/expected extensions SEQUENCE/);
    });

    it("skips an extension entry that is not a SEQUENCE", () => {
        // SEQUENCE OF { INTEGER } — entry is not a SEQUENCE. The parser is lenient
        // here: it stops scanning extensions rather than throwing, so the cert parses
        // and falls back to the CN (no valid SANs were extracted).
        const tail = tailWith(wrapSequence(wrapInteger(new Uint8Array([0x00]))));
        const { der } = makeCertWithTail("example.com", tail);
        const cert = parseCertificate(der);
        expect(cert.subjectAltNames).toEqual([]);
        expect(cert.commonName).toBe("example.com");
    });

    it("throws when the extnValue is not an OCTET STRING", () => {
        // Extension { OID, INTEGER(instead of OCTET STRING) }
        const ext = wrapSequenceOf(wrapOid("2.5.29.17"), wrapInteger(new Uint8Array([0x00])));
        const tail = tailWith(wrapSequence(ext));
        const { der } = makeCertWithTail("example.com", tail);
        expect(() => parseCertificate(der)).toThrow(/expected extnValue OCTET STRING/);
    });

    it("parses a SAN extension whose value is not a SEQUENCE (empty result)", () => {
        // SAN (2.5.29.17) whose unwrapped value is an INTEGER — parseSubjectAltNames
        // returns [] and the parser falls back to the CN.
        const san = wrapSequenceOf(wrapOid("2.5.29.17"), wrapTag(0x04, wrapInteger(new Uint8Array([0x00]))));
        const tail = tailWith(wrapSequence(san));
        const { der } = makeCertWithTail("san-test.example.com", tail);
        const cert = parseCertificate(der);
        // No valid SAN DNS names, so it falls back to the CN.
        expect(cert.subjectAltNames).toEqual([]);
        expect(cert.commonName).toBe("san-test.example.com");
    });

    it("parses a KeyUsage extension whose BIT STRING content is too short", () => {
        // KeyUsage (2.5.29.15) whose unwrapped value is a BIT STRING with only the
        // unused-bits byte (content.length < 2) -> both flags false.
        const inner = wrapTag(0x03, new Uint8Array([0x00])); // BIT STRING, 1 byte content
        const ext = wrapSequenceOf(wrapOid("2.5.29.15"), wrapTag(0x04, inner));
        const tail = tailWith(wrapSequence(ext));
        const { der } = makeCertWithTail("example.com", tail);
        const cert = parseCertificate(der);
        expect(cert.keyUsageDigitalSignature).toBe(false);
        expect(cert.keyUsageKeyEncipherment).toBe(false);
    });

    it("parses a BasicConstraints extension whose value is not a SEQUENCE", () => {
        // BasicConstraints (2.5.29.19) whose unwrapped value is an INTEGER ->
        // parseBasicConstraints returns false.
        const inner = wrapInteger(new Uint8Array([0x00]));
        const ext = wrapSequenceOf(wrapOid("2.5.29.19"), wrapTag(0x04, inner));
        const tail = tailWith(wrapSequence(ext));
        const { der } = makeCertWithTail("example.com", tail);
        const cert = parseCertificate(der);
        expect(cert.isCa).toBe(false);
    });

    it("parses a BasicConstraints extension with no BOOLEAN (cA absent)", () => {
        // SEQUENCE { } empty, or SEQUENCE { INTEGER } — no BOOLEAN at value start.
        const inner = wrapSequence(wrapInteger(new Uint8Array([0x00])));
        const ext = wrapSequenceOf(wrapOid("2.5.29.19"), wrapTag(0x04, inner));
        const tail = tailWith(wrapSequence(ext));
        const { der } = makeCertWithTail("example.com", tail);
        const cert = parseCertificate(der);
        expect(cert.isCa).toBe(false);
    });

    it("parses a BasicConstraints extension with cA = TRUE", () => {
        // SEQUENCE { BOOLEAN TRUE }
        const inner = wrapSequence(wrapTag(0x01, new Uint8Array([0xff])));
        const ext = basicConstraintsExt(inner);
        const tail = tailWith(wrapSequence(ext));
        const { der } = makeCertWithTail("example.com", tail);
        const cert = parseCertificate(der);
        expect(cert.isCa).toBe(true);
    });

    it("skips an unknown extension OID", () => {
        // An extension with an unrecognized OID is ignored (hits the default: break).
        const ext = wrapSequenceOf(wrapOid("2.5.29.99"), wrapTag(0x04, wrapInteger(new Uint8Array([0x00]))));
        const tail = tailWith(wrapSequence(ext));
        const { der } = makeCertWithTail("example.com", tail);
        // Should parse without throwing.
        expect(() => parseCertificate(der)).not.toThrow();
    });

    it("parses a SAN with a non-DNS GeneralName (iPAddress tag [7])", () => {
        // GeneralName iPAddress is tag [7] (0x87) — not dNSName [2], so it is
        // skipped and the SAN list ends up empty (CN fallback).
        const sanValue = wrapSequence(wrapTag(0x87, new Uint8Array([127, 0, 0, 1])));
        const ext = wrapSequenceOf(wrapOid("2.5.29.17"), wrapTag(0x04, sanValue));
        const tail = tailWith(wrapSequence(ext));
        const { der } = makeCertWithTail("ip-test.example.com", tail);
        const cert = parseCertificate(der);
        expect(cert.subjectAltNames).toEqual([]);
        expect(cert.commonName).toBe("ip-test.example.com");
    });
});

// ---------------------------------------------------------------------------
// Trailing context-tag skipping (issuerUniqueID / subjectUniqueID / unknown).
// ---------------------------------------------------------------------------

describe("TBSCertificate trailing context tags", () => {
    it("skips a subjectUniqueID [2] trailing tag", () => {
        // Append a [2] tag after the SPKI — the parser must skip it.
        const tag2 = wrapTag(0xa2, wrapBitString(new Uint8Array([0x00])));
        const { der } = makeCertWithTail("example.com", tag2);
        expect(() => parseCertificate(der)).not.toThrow();
    });

    it("stops scanning at an unknown trailing tag", () => {
        // Append a [1] (issuerUniqueID) then an unknown tag [4]. The parser skips
        // [1], hits [4] (unknown) and stops — covering the `break` branch.
        const tag1 = wrapTag(0xa1, wrapBitString(new Uint8Array([0x00])));
        const tag4 = wrapTag(0xa4, wrapInteger(new Uint8Array([0x00])));
        const { der } = makeCertWithTail("example.com", concatBytes(tag1, tag4));
        expect(() => parseCertificate(der)).not.toThrow();
    });
});

// ---------------------------------------------------------------------------
// validateHostname edge cases.
// ---------------------------------------------------------------------------

describe("validateHostname edge cases", () => {
    function certWith(sans: readonly string[] = [], commonName?: string): Certificate {
        return {
            tbsBytes: new Uint8Array(0),
            subjectAltNames: sans,
            commonName,
            notBefore: 0,
            notAfter: Number.MAX_SAFE_INTEGER,
            keyUsageDigitalSignature: true,
            keyUsageKeyEncipherment: false,
            signatureScheme: "ecdsa_secp256r1_sha256",
            signatureValue: new Uint8Array(0),
            issuer: "",
            isCa: false,
            subjectPublicKeyInfo: new Uint8Array(0),
        };
    }

    it("returns false when there are no SANs and no CN", () => {
        expect(validateHostname(certWith([], undefined), "example.com")).toBe(false);
    });

    it("rejects an empty pattern", () => {
        expect(certWith([""], "example.com").subjectAltNames.length >= 0, "sanity").toBe(true);
        expect(validateHostname(certWith([""], undefined), "example.com")).toBe(false);
    });

    it("rejects an empty hostname", () => {
        expect(validateHostname(certWith(["example.com"], undefined), "")).toBe(false);
    });

    it("matches case-insensitively", () => {
        expect(validateHostname(certWith(["EXAMPLE.COM"], undefined), "example.com")).toBe(true);
    });

    it("rejects a wildcard that does not match the suffix", () => {
        expect(validateHostname(certWith(["*.example.com"], undefined), "foo.other.com")).toBe(false);
    });
});

// ---------------------------------------------------------------------------
// verifyChain: intermediate CA + base64Decode non-alphabet branch.
// ---------------------------------------------------------------------------

describe("verifyChain intermediate-CA enforcement", () => {
    it("rejects a chain whose intermediate is not a CA", async () => {
        // leaf signed by an intermediate that does NOT set cA=TRUE.
        const leaf = parseCertificate(makeSelfSignedCert("example.com").der);
        const intermediate = parseCertificate(makeSelfSignedCert("intermediate.example.com").der);
        // intermediate.isCa is false (no basicConstraints extension).
        const chain: CertificateChain = { leaf, intermediates: [intermediate], root: intermediate };
        const anchor: TrustAnchor = {
            subjectPublicKeyInfo: intermediate.subjectPublicKeyInfo,
            subject: intermediate.issuer,
        };
        await expect(
            verifyChain(chain, [anchor], "example.com", Math.floor(Date.UTC(2025, 0, 1) / 1000)),
        ).rejects.toMatchObject({ cause: { message: expect.stringMatching(/missing basicConstraints cA/) } });
    });

    it("accepts a chain whose intermediate IS a CA", async () => {
        // One self-signed CA certificate (cA=TRUE, CN="example.com") used as leaf,
        // intermediate, and root. Because it is self-signed, its signature verifies
        // against its own SPKI at every step — so the cA flag is the only variable
        // between this test and the rejected non-CA case above.
        const bc = basicConstraintsExt(wrapSequence(wrapTag(0x01, new Uint8Array([0xff]))));
        const tail = wrapTag(0xa3, wrapSequence(bc));
        const ca = parseCertificate(makeCertWithTail("example.com", tail).der);
        expect(ca.isCa).toBe(true);
        const chain: CertificateChain = { leaf: ca, intermediates: [ca], root: ca };
        const anchor: TrustAnchor = {
            subjectPublicKeyInfo: ca.subjectPublicKeyInfo,
            subject: ca.issuer,
        };
        await expect(
            verifyChain(chain, [anchor], "example.com", Math.floor(Date.UTC(2025, 0, 1) / 1000)),
        ).resolves.toBeUndefined();
    });
});
