/**
 * Tests for @browsercore/tls certificate handling (Step 4).
 *
 * The test file uses node:crypto to generate a real self-signed ECDSA P-256
 * certificate — that's fine: the production code routes through @browsercore/crypto
 * and never imports node:crypto. Here we exercise parseCertificate,
 * validateHostname, verifyChain, and pemToDer against a real DER cert.
 */

import { describe, it, expect } from "vitest";
import {
    generateKeyPairSync,
    createSign,
    createHash,
    type KeyObject,
} from "node:crypto";
import { X509Certificate } from "node:crypto";

import {
    parseCertificate,
    validateHostname,
    verifyChain,
    pemToDer,
} from "../src/certificates/certificates.js";
import type { Certificate, CertificateChain, TrustAnchor } from "../src/certificates/certificates.js";
import { TlsHandshakeError } from "../src/errors.js";

/**
 * Build a minimal DER-encoded TBSCertificate for an ECDSA P-256 self-signed
 * leaf. We hand-roll the ASN.1 here (it's test-only scaffolding) so we control
 * the exact bytes parseCertificate must decode.
 */
function encodeTbsCertificate(publicKeyDer: Uint8Array, commonName: string): {
    tbs: Uint8Array;
    tbsBytes: Uint8Array;
} {
    const encoder = new TextEncoder();
    const cnBytes = encoder.encode(commonName);

    // CommonName OID 2.5.4.3 with the value as a UTF8String.
    const cnValue = wrapUtf8String(cnBytes);
    const cnAtv = wrapSequenceOf(wrapOid("2.5.4.3"), cnValue); // AttributeTypeAndValue
    const cnRdn = wrapSetOf(cnAtv); // RelativeDistinguishedName
    const subject = wrapSequenceOf(cnRdn);

    // signature AlgorithmIdentifier: ecdsa-with-SHA256 (1.2.840.10045.4.3.2), NULL params.
    const sigAlg = wrapSequenceOf(wrapOid("1.2.840.10045.4.3.2"), wrapNull());

    // validity: two GeneralizedTime values (30 days window starting 2024-01-01).
    const notBefore = wrapGeneralizedTime("20240101000000Z");
    const notAfter = wrapGeneralizedTime("20340101000000Z");
    const validity = wrapSequenceOf(notBefore, notAfter);

    const serial = wrapInteger(new Uint8Array([0x01]));

    // subjectPublicKeyInfo: algorithm + the raw P-256 SPKI BIT STRING-ish. To keep
    // this simple we wrap the already-encoded SPKI SEQUENCE the key generator
    // gave us — but node's SPKI is itself a SEQUENCE, so we just embed it.
    const spki = publicKeyDer;

    // Assemble the TBSCertificate fields in order (version omitted = v1 default).
    const tbsBody = concatBytes(
        serial,
        sigAlg,
        subject, // issuer == subject for self-signed
        validity,
        subject,
        spki,
    );
    const tbs = wrapSequence(tbsBody);
    return { tbs, tbsBytes: tbs };
}

/** Build the outer Certificate: SEQUENCE { tbs, sigAlg, sigValue }. */
function encodeCertificate(tbsBytes: Uint8Array, signatureDer: Uint8Array): Uint8Array {
    const sigAlg = wrapSequenceOf(wrapOid("1.2.840.10045.4.3.2"), wrapNull());
    // signatureValue is a BIT STRING with 0 unused bits.
    const sigValue = wrapBitString(signatureDer);
    return wrapSequence(concatBytes(tbsBytes, sigAlg, sigValue));
}

// --- tiny ASN.1 test helpers ---

function wrapTag(tag: number, content: Uint8Array): Uint8Array {
    return concatBytes(encodeTag(tag), encodeLength(content.length), content);
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

function wrapSequence(content: Uint8Array): Uint8Array {
    return wrapTag(0x30, content);
}
/** Wrap a SEQUENCE whose body is the concatenation of several pre-encoded parts. */
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
    // First byte encodes the first two arcs: parts[0] * 40 + parts[1].
    const first = parts[0]! * 40 + parts[1]!;
    const rest: number[] = [];
    for (const arc of parts.slice(2)) {
        // base-128 encode each subsequent arc.
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
    // Ensure positive: prepend 0x00 if the high bit is set.
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

/** Generate a self-signed ECDSA P-256 certificate DER for the given commonName. */
function makeSelfSignedCert(commonName: string): { der: Uint8Array; pem: string } {
    const { publicKey, privateKey } = generateKeyPairSync("ec", {
        namedCurve: "P-256",
        publicKeyEncoding: { type: "spki", format: "der" },
        privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });

    const publicKeyDer = new Uint8Array(publicKey);
    const { tbsBytes } = encodeTbsCertificate(publicKeyDer, commonName);

    // Sign the TBSCertificate with ECDSA-SHA256 (DER-encoded signature).
    const signer = createSign("SHA256");
    signer.update(Buffer.from(tbsBytes));
    const signature = new Uint8Array(signer.sign({ key: privateKey, dsaEncoding: "der" }));

    const der = encodeCertificate(tbsBytes, signature);
    const pem = derToPem(der);
    return { der, pem };
}

function derToPem(der: Uint8Array): string {
    const b64 = Buffer.from(der).toString("base64");
    const lines = b64.match(/.{1,64}/g) ?? [b64];
    return `-----BEGIN CERTIFICATE-----\n${lines.join("\n")}\n-----END CERTIFICATE-----\n`;
}

describe("pemToDer", () => {
    it("round-trips a PEM certificate back to DER", () => {
        const { der, pem } = makeSelfSignedCert("example.com");
        const recovered = pemToDer(pem);
        expect(recovered).toEqual(der);
    });

    it("strips varying whitespace between the markers", () => {
        const { der } = makeSelfSignedCert("example.com");
        const b64 = Buffer.from(der).toString("base64");
        const pem = `-----BEGIN CERTIFICATE-----\r\n${b64.slice(0, 30)} ${b64.slice(30)} \t\n-----END CERTIFICATE-----`;
        expect(pemToDer(pem)).toEqual(der);
    });

    it("throws on missing markers", () => {
        expect(() => pemToDer("not a pem")).toThrow(/BEGIN\/END/);
    });
});

describe("parseCertificate", () => {
    it("parses a self-signed ECDSA P-256 certificate and recovers its fields", () => {
        const { der } = makeSelfSignedCert("example.com");
        const cert = parseCertificate(der);

        expect(cert.signatureScheme).toBe("ecdsa_secp256r1_sha256");
        expect(cert.commonName).toBe("example.com");
        expect(cert.subjectAltNames).toEqual([]);
        expect(cert.subjectPublicKeyInfo.length).toBeGreaterThan(0);
        // Validity window we encoded: 2024..2034.
        expect(cert.notBefore).toBeLessThan(cert.notAfter);
        expect(cert.isCa).toBe(false); // no basicConstraints extension
    });

    it("captures tbsBytes that re-encode to the exact TBSCertificate", () => {
        const { der } = makeSelfSignedCert("example.com");
        const cert = parseCertificate(der);
        // The TBSCertificate is a SEQUENCE; its first byte must be 0x30 and the
        // span must be a subarray of the full Certificate DER.
        expect(cert.tbsBytes[0]).toBe(0x30);
        expect(cert.tbsBytes.length).toBeLessThan(der.length);
        // The outer Certificate is SEQUENCE { tbs, sigAlg, sigValue }, so the
        // TBSCertificate starts right after the outer header. Re-derive that
        // offset from the outer length encoding and confirm an exact match.
        const outerLengthByte = der[1]!;
        const headerLen = outerLengthByte < 0x80 ? 2 : 2 + (outerLengthByte & 0x7f);
        expect(Buffer.from(der.subarray(headerLen, headerLen + cert.tbsBytes.length)).equals(
            Buffer.from(cert.tbsBytes),
        )).toBe(true);
    });

    it("throws TlsHandshakeError on truncated input", () => {
        const { der } = makeSelfSignedCert("example.com");
        const truncated = der.subarray(0, der.length - 5);
        expect(() => parseCertificate(truncated)).toThrow(TlsHandshakeError);
    });

    it("throws TlsHandshakeError on garbage input", () => {
        expect(() => parseCertificate(new Uint8Array([0x30, 0x02, 0x00, 0x00]))).toThrow(TlsHandshakeError);
    });
});

describe("validateHostname", () => {
    function certWith(commonName: string, sans: readonly string[] = []): Certificate {
        return {
            tbsBytes: new Uint8Array(0),
            subjectPublicKeyInfo: new Uint8Array(0),
            subjectAltNames: sans,
            commonName: sans.length === 0 ? commonName : undefined,
            notBefore: 0,
            notAfter: Number.MAX_SAFE_INTEGER,
            keyUsageDigitalSignature: true,
            keyUsageKeyEncipherment: false,
            signatureScheme: "ecdsa_secp256r1_sha256",
            signatureValue: new Uint8Array(0),
            issuer: "",
            isCa: false,
        };
    }

    it("matches a SAN DNS name exactly", () => {
        expect(validateHostname(certWith("", ["example.com"]), "example.com")).toBe(true);
    });

    it("rejects a hostname that is not in the SAN list", () => {
        expect(validateHostname(certWith("", ["example.com"]), "other.com")).toBe(false);
    });

    it("matches a wildcard SAN against a single left label", () => {
        expect(validateHostname(certWith("", ["*.example.com"]), "foo.example.com")).toBe(true);
    });

    it("rejects a wildcard SAN crossing a dot", () => {
        expect(validateHostname(certWith("", ["*.example.com"]), "bar.foo.example.com")).toBe(false);
    });

    it("rejects a wildcard SAN matching the bare apex", () => {
        expect(validateHostname(certWith("", ["*.example.com"]), "example.com")).toBe(false);
    });

    it("falls back to CN when no SAN DNS names are present", () => {
        expect(validateHostname(certWith("legacy.example.org"), "legacy.example.org")).toBe(true);
        expect(validateHostname(certWith("legacy.example.org"), "wrong.org")).toBe(false);
    });

    it("SAN takes precedence over CN", () => {
        const cert = certWith("cn.example.com", ["san.example.com"]);
        expect(validateHostname(cert, "san.example.com")).toBe(true);
        expect(validateHostname(cert, "cn.example.com")).toBe(false);
    });
});

describe("verifyChain", () => {
    it("verifies a self-signed certificate against its own SPKI as trust anchor", async () => {
        const { der } = makeSelfSignedCert("example.com");
        const leaf = parseCertificate(der);
        const chain: CertificateChain = {
            leaf,
            intermediates: [],
            root: leaf, // self-signed: the leaf is also the root
        };
        const anchor: TrustAnchor = {
            subjectPublicKeyInfo: leaf.subjectPublicKeyInfo,
            subject: leaf.issuer,
        };
        // Should not throw.
        await verifyChain(chain, [anchor], "example.com", Math.floor(Date.UTC(2025, 0, 1) / 1000));
    });

    it("rejects a hostname mismatch", async () => {
        const { der } = makeSelfSignedCert("example.com");
        const leaf = parseCertificate(der);
        const chain: CertificateChain = { leaf, intermediates: [], root: leaf };
        const anchor: TrustAnchor = {
            subjectPublicKeyInfo: leaf.subjectPublicKeyInfo,
            subject: leaf.issuer,
        };
        await expect(
            verifyChain(chain, [anchor], "wrong.com", Math.floor(Date.UTC(2025, 0, 1) / 1000)),
        ).rejects.toThrow(TlsHandshakeError);
    });

    it("rejects an expired certificate", async () => {
        const { der } = makeSelfSignedCert("example.com");
        const leaf = parseCertificate(der);
        const chain: CertificateChain = { leaf, intermediates: [], root: leaf };
        const anchor: TrustAnchor = {
            subjectPublicKeyInfo: leaf.subjectPublicKeyInfo,
            subject: leaf.issuer,
        };
        // 2035 is past the 2034 notAfter we encoded. The detail lives in the
        // `.cause`; the outer message is the generic phase string.
        await expect(
            verifyChain(chain, [anchor], "example.com", Math.floor(Date.UTC(2035, 0, 1) / 1000)),
        ).rejects.toMatchObject({ cause: { message: expect.stringMatching(/not valid/) } });
    });

    it("rejects a root that does not match any trust anchor", async () => {
        const { der } = makeSelfSignedCert("example.com");
        const leaf = parseCertificate(der);
        const chain: CertificateChain = { leaf, intermediates: [], root: leaf };
        const wrongAnchor: TrustAnchor = {
            subjectPublicKeyInfo: new Uint8Array(32).fill(0xff),
            subject: "nobody",
        };
        await expect(
            verifyChain(chain, [wrongAnchor], "example.com", Math.floor(Date.UTC(2025, 0, 1) / 1000)),
        ).rejects.toMatchObject({ cause: { message: expect.stringMatching(/trust anchor/) } });
    });

    it("rejects a chain whose signature does not verify", async () => {
        const good = makeSelfSignedCert("example.com");
        const other = makeSelfSignedCert("example.com");
        const leaf = parseCertificate(good.der);
        // Use a different cert as the "root" — its SPKI won't verify the leaf's
        // signature, so verifyChain must reject.
        const wrongRoot = parseCertificate(other.der);
        const chain: CertificateChain = { leaf, intermediates: [], root: wrongRoot };
        const anchor: TrustAnchor = {
            subjectPublicKeyInfo: wrongRoot.subjectPublicKeyInfo,
            subject: wrongRoot.issuer,
        };
        await expect(
            verifyChain(chain, [anchor], "example.com", Math.floor(Date.UTC(2025, 0, 1) / 1000)),
        ).rejects.toMatchObject({ cause: { message: expect.stringMatching(/signature verification failed/) } });
    });
});
