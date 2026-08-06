/**
 * Tests for @browsercore/tls connection handshake-message helpers.
 *
 * ALPN extraction from EncryptedExtensions, Certificate message parsing and
 * chain validation, client Finished construction, and the encrypted-handshake
 * message reader (decrypt + inner-type recovery + buffer threading).
 */

import { describe, it, expect } from "vitest";
import { crypto } from "@browsercore/crypto";
import { generateKeyPairSync, createSign } from "node:crypto";
import {
    parseAlpnFromEncryptedExtensions,
    parseCertificateMessage,
    validateCertificateChain,
    buildClientFinishedMessage,
    readEncryptedHandshakeMessage,
} from "../src/connection/handshake-messages.js";
import { xorNonce } from "../src/connection/record-layer.js";
import { ContentType, encryptRecord, serializeRecordHeader } from "../src/record/record.js";
import { ExtensionType } from "../src/extensions/extensions.js";
import { TlsHandshakeError, TlsDecryptError } from "../src/errors.js";
import { FakeTransport } from "./fake-transport.js";

// ---------------------------------------------------------------------------
// DER helpers (test-only scaffolding, mirrors certificates.test.ts)
// ---------------------------------------------------------------------------

function concatBytes(...chunks: Uint8Array[]): Uint8Array {
    const total = chunks.reduce((s, c) => s + c.length, 0);
    const out = new Uint8Array(total);
    let o = 0;
    for (const c of chunks) { out.set(c, o); o += c.length; }
    return out;
}
function derTagged(tag: number, content: Uint8Array): Uint8Array {
    const len = content.length < 0x80
        ? new Uint8Array([content.length])
        : content.length < 0x100
            ? new Uint8Array([0x81, content.length])
            : new Uint8Array([0x82, (content.length >> 8) & 0xff, content.length & 0xff]);
    return concatBytes(new Uint8Array([tag]), len, content);
}
function derSequence(...parts: Uint8Array[]): Uint8Array { return derTagged(0x30, concatBytes(...parts)); }
function derSet(...parts: Uint8Array[]): Uint8Array { return derTagged(0x31, concatBytes(...parts)); }
function derNull(): Uint8Array { return new Uint8Array([0x05, 0x00]); }
function derInteger(value: Uint8Array): Uint8Array {
    const pad = value.length > 0 && (value[0]! & 0x80) !== 0;
    return derTagged(0x02, pad ? concatBytes(new Uint8Array([0x00]), value) : value);
}
function derBitString(content: Uint8Array): Uint8Array { return derTagged(0x03, concatBytes(new Uint8Array([0x00]), content)); }
function derUtf8String(bytes: Uint8Array): Uint8Array { return derTagged(0x0c, bytes); }
function derGeneralizedTime(text: string): Uint8Array { return derTagged(0x18, new TextEncoder().encode(text)); }
function derOid(oid: string): Uint8Array {
    const parts = oid.split(".").map((p) => Number.parseInt(p, 10));
    const first = parts[0]! * 40 + parts[1]!;
    const rest: number[] = [];
    for (const arc of parts.slice(2)) {
        if (arc === 0) { rest.push(0); continue; }
        const bytes: number[] = [];
        let value = arc;
        while (value > 0) { bytes.unshift((value & 0x7f) | (bytes.length === 0 ? 0 : 0x80)); value >>= 7; }
        rest.push(...bytes);
    }
    return derTagged(0x06, new Uint8Array([first, ...rest]));
}

/** Build a self-signed ECDSA P-256 certificate DER for the given commonName. */
function makeSelfSignedCert(commonName: string): Uint8Array {
    const { publicKey, privateKey } = generateKeyPairSync("ec", {
        namedCurve: "P-256",
        publicKeyEncoding: { type: "spki", format: "der" },
        privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });
    const spki = new Uint8Array(publicKey);
    const cnValue = derUtf8String(new TextEncoder().encode(commonName));
    const name = derSequence(derSet(derSequence(derOid("2.5.4.3"), cnValue)));
    const sigAlg = derSequence(derOid("1.2.840.10045.4.3.2"), derNull());
    const validity = derSequence(derGeneralizedTime("20240101000000Z"), derGeneralizedTime("20340101000000Z"));
    const serial = derInteger(new Uint8Array([0x01]));
    const tbs = derSequence(concatBytes(serial, sigAlg, name, validity, name, spki));

    const signer = createSign("SHA256");
    signer.update(Buffer.from(tbs));
    const signature = new Uint8Array(signer.sign({ key: privateKey, dsaEncoding: "der" }));
    return derSequence(concatBytes(tbs, sigAlg, derBitString(signature)));
}

/** Build a Certificate handshake message body from one or more DER certs. */
function buildCertMessageBody(certs: Uint8Array[]): Uint8Array {
    const entries: Uint8Array[] = [];
    let entriesLen = 0;
    for (const cert of certs) {
        // cert_data length(3) || cert || extensions_len(2)=0
        const entry = new Uint8Array(3 + cert.length + 2);
        entry[0] = (cert.length >> 16) & 0xff;
        entry[1] = (cert.length >> 8) & 0xff;
        entry[2] = cert.length & 0xff;
        entry.set(cert, 3);
        entries.push(entry);
        entriesLen += entry.length;
    }
    const body = new Uint8Array(1 + 3 + entriesLen);
    let o = 0;
    body[o++] = 0; // request context length
    body[o++] = (entriesLen >> 16) & 0xff;
    body[o++] = (entriesLen >> 8) & 0xff;
    body[o++] = entriesLen & 0xff;
    for (const e of entries) { body.set(e, o); o += e.length; }
    return body;
}

// ---------------------------------------------------------------------------
// EncryptedExtensions / ALPN
// ---------------------------------------------------------------------------

/** Wrap a single extension's data in a length-prefixed extensions block. */
function extBlock(type: number, data: Uint8Array): Uint8Array {
    const ext = new Uint8Array(2 + 2 + 2 + data.length);
    ext[0] = 0x00;
    ext[1] = (2 + 2 + data.length) & 0xff;
    ext[2] = (type >> 8) & 0xff;
    ext[3] = type & 0xff;
    ext[4] = (data.length >> 8) & 0xff;
    ext[5] = data.length & 0xff;
    ext.set(data, 6);
    return ext;
}

/** ALPN extension body: list_len(2) || name_len(1) || name. */
function alpnBody(name: string): Uint8Array {
    const nameBytes = new TextEncoder().encode(name);
    const body = new Uint8Array(2 + 1 + nameBytes.length);
    body[0] = 0x00;
    body[1] = (1 + nameBytes.length) & 0xff;
    body[2] = nameBytes.length;
    body.set(nameBytes, 3);
    return body;
}

describe("parseAlpnFromEncryptedExtensions", () => {
    it("returns the negotiated ALPN protocol name", () => {
        const body = extBlock(ExtensionType.APPLICATION_LAYER_PROTOCOL_NEGOTIATION, alpnBody("h2"));
        expect(parseAlpnFromEncryptedExtensions(body)).toBe("h2");
    });

    it("returns undefined when there is no ALPN extension", () => {
        const body = extBlock(ExtensionType.SUPPORTED_VERSIONS, new Uint8Array([0x03, 0x04]));
        expect(parseAlpnFromEncryptedExtensions(body)).toBeUndefined();
    });

    it("returns undefined when the ALPN data is truncated (< 3 bytes)", () => {
        const body = extBlock(ExtensionType.APPLICATION_LAYER_PROTOCOL_NEGOTIATION, new Uint8Array([0x00, 0x01]));
        expect(parseAlpnFromEncryptedExtensions(body)).toBeUndefined();
    });

    it("returns undefined when the declared name length exceeds the data", () => {
        const body = extBlock(ExtensionType.APPLICATION_LAYER_PROTOCOL_NEGOTIATION, new Uint8Array([0x00, 0x01, 99]));
        expect(parseAlpnFromEncryptedExtensions(body)).toBeUndefined();
    });
});

// ---------------------------------------------------------------------------
// Certificate message parsing
// ---------------------------------------------------------------------------

describe("parseCertificateMessage", () => {
    it("parses a single-cert chain into leaf/root with no intermediates", () => {
        const der = makeSelfSignedCert("example.com");
        const body = buildCertMessageBody([der]);
        const chain = parseCertificateMessage(body);
        expect(chain.intermediates).toHaveLength(0);
        expect(chain.leaf.commonName).toBe("example.com");
        expect(chain.root).toBe(chain.leaf);
    });

    it("parses a multi-cert chain preserving leaf/intermediate/root order", () => {
        const leaf = makeSelfSignedCert("leaf.example.com");
        const inter = makeSelfSignedCert("intermediate.example.com");
        const root = makeSelfSignedCert("root.example.com");
        const body = buildCertMessageBody([leaf, inter, root]);
        const chain = parseCertificateMessage(body);
        expect(chain.leaf.commonName).toBe("leaf.example.com");
        expect(chain.root.commonName).toBe("root.example.com");
        expect(chain.intermediates).toHaveLength(1);
        expect(chain.intermediates[0]!.commonName).toBe("intermediate.example.com");
    });

    it("throws when the certificate_list is empty", () => {
        const body = buildCertMessageBody([]);
        expect(() => parseCertificateMessage(body)).toThrow(TlsHandshakeError);
        try {
            parseCertificateMessage(body);
        } catch (e) {
            expect((e as TlsHandshakeError).cause?.message).toMatch(/empty certificate_list/);
        }
    });

    it("throws when the list length exceeds the body", () => {
        const body = new Uint8Array([0x00, 0xff, 0xff, 0xff]);
        expect(() => parseCertificateMessage(body)).toThrow(TlsHandshakeError);
    });

    it("throws when the body is truncated mid-read", () => {
        const body = new Uint8Array([0x00]);
        expect(() => parseCertificateMessage(body)).toThrow(TlsHandshakeError);
    });
});

describe("validateCertificateChain", () => {
    it("passes hostname validation and returns the chain when the CN matches", async () => {
        const der = makeSelfSignedCert("example.com");
        const body = buildCertMessageBody([der]);
        const chain = await validateCertificateChain(body, "example.com", [], 1_700_000_000, crypto);
        expect(chain.leaf.commonName).toBe("example.com");
    });

    it("throws when the server name does not match the leaf CN", async () => {
        const der = makeSelfSignedCert("example.com");
        const body = buildCertMessageBody([der]);
        await expect(
            validateCertificateChain(body, "evil.com", [], 1_700_000_000, crypto),
        ).rejects.toThrow(TlsHandshakeError);
        try {
            await validateCertificateChain(body, "evil.com", [], 1_700_000_000, crypto);
        } catch (e) {
            expect((e as TlsHandshakeError).cause?.message).toMatch(/does not match/);
        }
    });

    it("runs full chain verification when trust anchors are provided", async () => {
        // A self-signed cert presented as its own trust anchor: the leaf is the
        // root, its SPKI matches the anchor, and the hostname is valid.
        const der = makeSelfSignedCert("example.com");
        const body = buildCertMessageBody([der]);
        // now must fall inside the cert's validity window (2024..2034).
        const chain = await validateCertificateChain(body, "example.com", [der], 1_800_000_000, crypto);
        expect(chain.leaf.commonName).toBe("example.com");
    });

    it("fails chain verification when the leaf is not anchored by a trust anchor", async () => {
        const leafDer = makeSelfSignedCert("example.com");
        const unrelatedAnchor = makeSelfSignedCert("ca.example.com");
        const body = buildCertMessageBody([leafDer]);
        await expect(
            validateCertificateChain(body, "example.com", [unrelatedAnchor], 1_800_000_000, crypto),
        ).rejects.toThrow(TlsHandshakeError);
    });
});

// ---------------------------------------------------------------------------
// Client Finished construction
// ---------------------------------------------------------------------------

describe("buildClientFinishedMessage", () => {
    it("emits a Finished handshake message with type 20 and a verify_data body", () => {
        const secret = new Uint8Array(32).fill(0x7c);
        const transcript = [new Uint8Array([1, 2, 3]), new Uint8Array([4, 5])];
        const msg = buildClientFinishedMessage("SHA-256", secret, transcript, crypto);
        expect(msg[0]).toBe(20); // HandshakeType.FINISHED
        const bodyLen = (msg[1]! << 16) | (msg[2]! << 8) | msg[3]!;
        expect(bodyLen).toBe(32); // SHA-256 verify_data length
        expect(msg.length).toBe(4 + 32);
    });

    it("produces a 48-byte verify_data for SHA-384", () => {
        const secret = new Uint8Array(48).fill(0x7c);
        const msg = buildClientFinishedMessage("SHA-384", secret, [], crypto);
        const bodyLen = (msg[1]! << 16) | (msg[2]! << 8) | msg[3]!;
        expect(bodyLen).toBe(48);
    });
});

// ---------------------------------------------------------------------------
// Encrypted handshake message reader
// ---------------------------------------------------------------------------

const HS_TRAFFIC = {
    key: new Uint8Array(16).fill(0xde),
    iv: new Uint8Array(12).fill(0xf0),
};

/** Encrypt a handshake message into a standalone APPLICATION_DATA record. */
function encryptHandshakeRecord(content: Uint8Array, seq: number, traffic = HS_TRAFFIC): Uint8Array {
    const plaintext = new Uint8Array(content.length + 1);
    plaintext.set(content, 0);
    plaintext[content.length] = ContentType.HANDSHAKE; // inner type
    const header = serializeRecordHeader(ContentType.APPLICATION_DATA, plaintext.length + 16);
    const nonce = xorNonce(traffic.iv, seq);
    const ciphertext = encryptRecord(plaintext, traffic.key, nonce, header, "AES-128-GCM", crypto);
    return concatBytes(header, ciphertext);
}

describe("readEncryptedHandshakeMessage", () => {
    it("decrypts a handshake message and splits it into whole + body", async () => {
        const body = new Uint8Array([0xaa, 0xbb, 0xcc]);
        const whole = new Uint8Array(4 + body.length);
        whole[0] = 8;
        whole[3] = body.length;
        whole.set(body, 4);

        const record = encryptHandshakeRecord(whole, 0);
        const result = await readEncryptedHandshakeMessage(record, new FakeTransport(), "AES-128-GCM", HS_TRAFFIC, 0, crypto);
        expect(result.whole).toEqual(whole);
        expect(result.body).toEqual(body);
        expect(result.readBuffer.length).toBe(0);
    });

    it("throws when the outer record type is not application_data", async () => {
        const header = serializeRecordHeader(ContentType.HANDSHAKE, 4);
        const buf = concatBytes(header, new Uint8Array(4));
        await expect(
            readEncryptedHandshakeMessage(buf, new FakeTransport(), "AES-128-GCM", HS_TRAFFIC, 0, crypto),
        ).rejects.toThrow(TlsHandshakeError);
    });

    it("throws when the inner content type is not handshake", async () => {
        const content = new Uint8Array([1, 2, 3]);
        const plaintext = new Uint8Array(content.length + 1);
        plaintext.set(content, 0);
        plaintext[content.length] = ContentType.APPLICATION_DATA;
        const header = serializeRecordHeader(ContentType.APPLICATION_DATA, plaintext.length + 16);
        const nonce = xorNonce(HS_TRAFFIC.iv, 0);
        const ciphertext = encryptRecord(plaintext, HS_TRAFFIC.key, nonce, header, "AES-128-GCM", crypto);
        await expect(
            readEncryptedHandshakeMessage(concatBytes(header, ciphertext), new FakeTransport(), "AES-128-GCM", HS_TRAFFIC, 0, crypto),
        ).rejects.toThrow(TlsHandshakeError);
    });

    it("throws when the plaintext is all zero padding (no inner type byte)", async () => {
        const zeros = new Uint8Array(4).fill(0);
        const header = serializeRecordHeader(ContentType.APPLICATION_DATA, zeros.length + 16);
        const nonce = xorNonce(HS_TRAFFIC.iv, 0);
        const ciphertext = encryptRecord(zeros, HS_TRAFFIC.key, nonce, header, "AES-128-GCM", crypto);
        await expect(
            readEncryptedHandshakeMessage(concatBytes(header, ciphertext), new FakeTransport(), "AES-128-GCM", HS_TRAFFIC, 0, crypto),
        ).rejects.toThrow(TlsHandshakeError);
    });

    it("throws TlsDecryptError when the key is wrong (auth failure)", async () => {
        const whole = new Uint8Array([0, 0, 0, 1, 0x42]);
        const record = encryptHandshakeRecord(whole, 0);
        const wrong = { key: new Uint8Array(16).fill(0x00), iv: HS_TRAFFIC.iv };
        await expect(
            readEncryptedHandshakeMessage(record, new FakeTransport(), "AES-128-GCM", wrong, 0, crypto),
        ).rejects.toThrow(TlsDecryptError);
    });
});
