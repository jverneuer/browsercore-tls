/**
 * Minimal TLS 1.3 server simulator for handshake-driver tests.
 *
 * Mirrors the server's side of RFC 8446 just enough to drive the client's
 * runHandshake to completion: parse the ClientHello's key share, build a
 * ServerHello + encrypted flight (EncryptedExtensions, Certificate,
 * CertificateVerify, Finished), and encrypt each under the server handshake
 * traffic key. Everything is real crypto — the only shortcut is that
 * CertificateVerify carries a dummy signature (the client driver does not
 * verify it; only the Finished HMAC is checked).
 */

import { createTestCryptoProvider } from "./test-helpers.js";
import type { X25519Backend } from "@browsercore/crypto";

const crypto = createTestCryptoProvider();
import { generateKeyPairSync, createSign } from "node:crypto";
import {
    ContentType,
    serializeRecordHeader,
    encryptRecord,
} from "../src/record/record.js";
import { ExtensionType, namedGroupToWire, parseExtensions, findExtension } from "../src/extensions/extensions.js";
import { HandshakeType } from "../src/handshake/handshake.js";
import {
    deriveHandshakeTrafficSecrets,
    deriveTrafficSecrets,
    hkdfExpandLabel,
    hashLengthFor,
} from "../src/crypto/keySchedule.js";
import { transcriptHash } from "../src/connection/key-exchange.js";
import { xorNonce, AEAD_TAG_LENGTH } from "../src/connection/record-layer.js";

// --- DER helpers (mirrors certificates.test.ts) ---
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

export interface ServerOptions {
    /** ALPN protocol to negotiate in EncryptedExtensions (omit for none). */
    alpn?: string;
    /** Cipher suite wire value to negotiate (default 0x1301 = AES-128-GCM). */
    cipherWire?: number;
    /**
     * How to pack the server's encrypted flight into records.
     * - "separate" (default): one handshake message per record (the simple case).
     * - "coalesced": all four messages (EE + Cert + CV + Finished) in a single
     *   record — the common real-world pattern that caused the finished-phase stall.
     * - "partial": two messages per record (EE+Cert, then CV+Finished).
     */
    recordPacking?: "separate" | "coalesced" | "partial";
    /**
     * X25519 backend for the server-side shared secret. When set, the server
     * uses this independent backend rather than the shared `crypto` provider
     * the client drives — breaking the circular masking where both sides call
     * the same (potentially buggy) implementation.
     */
    x25519Backend?: X25519Backend;
}

export class TlsServerSim {
    private serverKeys = crypto.x25519GenerateKeyPair();
    private leafDer: Uint8Array;
    public responses: Uint8Array[] = [];
    private clientKeySharePub: Uint8Array | undefined;
    private clientHelloMsg: Uint8Array | undefined;
    private readonly opts: ServerOptions;
    private readonly x25519Backend: X25519Backend | undefined;

    constructor(opts: ServerOptions = {}) {
        this.opts = opts;
        this.x25519Backend = opts.x25519Backend;
        this.leafDer = this.makeSelfSignedCert("example.com");
    }

    /** Build a self-signed ECDSA P-256 certificate DER for the given CN. */
    private makeSelfSignedCert(commonName: string): Uint8Array {
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

    /** Extract the client's X25519 public key from a ClientHello handshake message. */
    private extractClientKeyShare(clientHelloMsg: Uint8Array): Uint8Array {
        // Walk the ClientHello to the extensions block.
        let o = 4; // skip type(1) + length(3)
        o += 2 + 32; // legacy_version(2) + random(32)
        const sidLen = clientHelloMsg[o]!; o += 1 + sidLen;
        const csLen = (clientHelloMsg[o]! << 8) | clientHelloMsg[o + 1]!; o += 2 + csLen;
        const compLen = clientHelloMsg[o]!; o += 1 + compLen;
        // Extensions: length-prefixed block (includes the 2-byte prefix).
        const extBlock = clientHelloMsg.subarray(o);
        const extensions = parseExtensions(extBlock);
        const ks = findExtension(extensions, ExtensionType.KEY_SHARE);
        if (ks === undefined) throw new Error("ClientHello has no key_share extension");
        // Client key_share: client_shares_len(2) || share { group(2), len(2), key }.
        // ks.data starts with the 2-byte client_shares_len. Real browsers may
        // prepend a GREASE key-share entry (group 0x0a0a), so we must scan for the
        // real X25519 (0x001d) group rather than blindly reading the first share.
        const data = ks.data;
        const sharesLen = (data[0]! << 8) | data[1]!;
        let s = 2;
        const end = 2 + sharesLen;
        while (s + 4 <= end) {
            const group = (data[s]! << 8) | data[s + 1]!;
            const keyLen = (data[s + 2]! << 8) | data[s + 3]!;
            if (group === 0x001d) {
                return data.subarray(s + 4, s + 4 + keyLen);
            }
            s += 4 + keyLen;
        }
        throw new Error("ClientHello key_share has no X25519 (0x001d) entry");
    }

    /** Build the ServerHello handshake message (type + length + body). */
    private buildServerHelloMessage(): Uint8Array {
        const random = new Uint8Array(32).fill(0x55);
        const cipherWire = this.opts.cipherWire ?? 0x1301;

        // supported_versions extension: type(2) + len(2) + 0x0304(2).
        const svData = new Uint8Array([0x03, 0x04]);
        const svExt = this.extension(ExtensionType.SUPPORTED_VERSIONS, svData);

        // key_share extension: type(2) + len(2) + group(2) + keyLen(2) + key.
        const ksData = new Uint8Array(4 + this.serverKeys.publicKey.length);
        const gw = namedGroupToWire("x25519");
        ksData[0] = (gw >> 8) & 0xff;
        ksData[1] = gw & 0xff;
        ksData[2] = (this.serverKeys.publicKey.length >> 8) & 0xff;
        ksData[3] = this.serverKeys.publicKey.length & 0xff;
        ksData.set(this.serverKeys.publicKey, 4);
        const ksExt = this.extension(ExtensionType.KEY_SHARE, ksData);

        const extBytes = concatBytes(svExt, ksExt);

        const body = new Uint8Array(2 + 32 + 1 + 2 + 1 + 2 + extBytes.length);
        let o = 0;
        body[o++] = 0x03; body[o++] = 0x03; // legacy_version
        body.set(random, o); o += 32;
        body[o++] = 0; // session_id_len
        body[o++] = (cipherWire >> 8) & 0xff;
        body[o++] = cipherWire & 0xff;
        body[o++] = 0; // compression
        body[o++] = (extBytes.length >> 8) & 0xff;
        body[o++] = extBytes.length & 0xff;
        body.set(extBytes, o);

        return this.handshakeMessage(HandshakeType.SERVER_HELLO, body);
    }

    /** Build the EncryptedExtensions handshake message. */
    private buildEncryptedExtensionsMessage(): Uint8Array {
        let extBytes: Uint8Array;
        if (this.opts.alpn !== undefined) {
            const name = new TextEncoder().encode(this.opts.alpn);
            // ALPN ext body: list_len(2) + name_len(1) + name.
            const alpnData = new Uint8Array(2 + 1 + name.length);
            alpnData[0] = 0x00;
            alpnData[1] = (1 + name.length) & 0xff;
            alpnData[2] = name.length;
            alpnData.set(name, 3);
            extBytes = this.extension(ExtensionType.APPLICATION_LAYER_PROTOCOL_NEGOTIATION, alpnData);
        } else {
            extBytes = new Uint8Array(0);
        }
        const body = new Uint8Array(2 + extBytes.length);
        body[0] = (extBytes.length >> 8) & 0xff;
        body[1] = extBytes.length & 0xff;
        body.set(extBytes, 2);
        return this.handshakeMessage(HandshakeType.ENCRYPTED_EXTENSIONS, body);
    }

    /** Build the Certificate handshake message with a single self-signed leaf. */
    private buildCertificateMessage(): Uint8Array {
        const cert = this.leafDer;
        const entry = new Uint8Array(3 + cert.length + 2);
        entry[0] = (cert.length >> 16) & 0xff;
        entry[1] = (cert.length >> 8) & 0xff;
        entry[2] = cert.length & 0xff;
        entry.set(cert, 3);
        const listLen = entry.length;
        const body = new Uint8Array(1 + 3 + listLen);
        let o = 0;
        body[o++] = 0; // request context length
        body[o++] = (listLen >> 16) & 0xff;
        body[o++] = (listLen >> 8) & 0xff;
        body[o++] = listLen & 0xff;
        body.set(entry, o);
        return this.handshakeMessage(HandshakeType.CERTIFICATE, body);
    }

    /** Build a CertificateVerify with a dummy signature (not verified by client). */
    private buildCertificateVerifyMessage(): Uint8Array {
        // signature_scheme(2) = ecdsa_secp256r1_sha256 (0x0403) + sig_len(2) + sig.
        const sig = new Uint8Array(64).fill(0xee);
        const body = new Uint8Array(2 + 2 + sig.length);
        body[0] = 0x04; body[1] = 0x03;
        body[2] = (sig.length >> 8) & 0xff;
        body[3] = sig.length & 0xff;
        body.set(sig, 4);
        return this.handshakeMessage(HandshakeType.CERTIFICATE_VERIFY, body);
    }

    /** Build the Finished message: verify_data = HMAC(finished_key, transcript). */
    private buildFinishedMessage(
        serverHsTrafficSecret: Uint8Array,
        transcriptBeforeFinished: readonly Uint8Array[],
    ): Uint8Array {
        const hash = "SHA-256" as const;
        const hashLen = hashLengthFor(hash);
        const finishedKey = hkdfExpandLabel(serverHsTrafficSecret, "finished", new Uint8Array(0), hashLen, hash, crypto);
        const verifyData = crypto.hmac(hash, finishedKey, transcriptHash(transcriptBeforeFinished, hash, crypto));
        return this.handshakeMessage(HandshakeType.FINISHED, verifyData);
    }

    /** Wrap a handshake body in the 4-byte header (type + 24-bit length). */
    private handshakeMessage(type: number, body: Uint8Array): Uint8Array {
        const msg = new Uint8Array(4 + body.length);
        msg[0] = type;
        msg[1] = (body.length >> 16) & 0xff;
        msg[2] = (body.length >> 8) & 0xff;
        msg[3] = body.length & 0xff;
        msg.set(body, 4);
        return msg;
    }

    /** Build a typed extension: type(2) + data_len(2) + data. */
    private extension(type: number, data: Uint8Array): Uint8Array {
        const ext = new Uint8Array(2 + 2 + data.length);
        ext[0] = (type >> 8) & 0xff;
        ext[1] = type & 0xff;
        ext[2] = (data.length >> 8) & 0xff;
        ext[3] = data.length & 0xff;
        ext.set(data, 4);
        return ext;
    }

    /** Encrypt a handshake message as a standalone APPLICATION_DATA record. */
    private encryptHandshakeRecord(
        msg: Uint8Array,
        traffic: { key: Uint8Array; iv: Uint8Array },
        seq: number,
    ): Uint8Array {
        const plaintext = concatBytes(msg, new Uint8Array([ContentType.HANDSHAKE]));
        const header = serializeRecordHeader(ContentType.APPLICATION_DATA, plaintext.length + AEAD_TAG_LENGTH);
        const nonce = xorNonce(traffic.iv, seq);
        const ciphertext = encryptRecord(plaintext, traffic.key, nonce, header, "AES-128-GCM", crypto);
        return concatBytes(header, ciphertext);
    }

    /**
     * Process a ClientHello record (5-byte header + handshake message) written
     * by the client. Builds the full server flight and populates `responses`
     * (ServerHello record + 4 encrypted records) for the transport to replay.
     */
    onClientHello(clientHelloRecord: Uint8Array): void {
        const clientHelloMsg = clientHelloRecord.subarray(5); // strip record header
        this.clientHelloMsg = clientHelloMsg;
        this.clientKeySharePub = this.extractClientKeyShare(clientHelloMsg);

        // ServerHello (plaintext handshake record).
        const serverHelloMsg = this.buildServerHelloMessage();
        const shRecord = concatBytes(
            serializeRecordHeader(ContentType.HANDSHAKE, serverHelloMsg.length),
            serverHelloMsg,
        );

        // Shared secret + handshake traffic secrets. Use the injected backend
        // when provided, otherwise fall back to the shared crypto provider.
        const sharedSecret = this.x25519Backend
            ? this.x25519Backend.sharedSecret(this.serverKeys.secretKey, this.clientKeySharePub)
            : crypto.x25519SharedSecret(this.serverKeys.secretKey, this.clientKeySharePub);
        const cipherSuite = "TLS_AES_128_GCM_SHA256" as const;
        const helloTranscript = [clientHelloMsg, serverHelloMsg];
        const helloHash = transcriptHash(helloTranscript, "SHA-256", crypto);
        const { clientTrafficSecret, serverTrafficSecret } =
            deriveHandshakeTrafficSecrets(sharedSecret, helloHash, cipherSuite, crypto);
        const serverHsTraffic = deriveTrafficSecrets(serverTrafficSecret, cipherSuite, "SHA-256", crypto);

        // Build the server flight messages (each pushed to the transcript as the
        // client will see them post-decryption).
        const ee = this.buildEncryptedExtensionsMessage();
        const cert = this.buildCertificateMessage();
        const cv = this.buildCertificateVerifyMessage();
        const transcriptBeforeFinished = [clientHelloMsg, serverHelloMsg, ee, cert, cv];
        const fin = this.buildFinishedMessage(serverTrafficSecret, transcriptBeforeFinished);

        // Encrypt the server flight under the server handshake key. RFC 8446
        // §5.1 permits coalescing multiple handshake messages into a single
        // record; real servers (Cloudflare, nginx, OpenSSL) commonly do so.
        const packing = this.opts.recordPacking ?? "separate";
        let encrypted: Uint8Array[];
        if (packing === "coalesced") {
            encrypted = [
                this.encryptHandshakeRecord(concatBytes(ee, cert, cv, fin), serverHsTraffic, 0),
            ];
        } else if (packing === "partial") {
            encrypted = [
                this.encryptHandshakeRecord(concatBytes(ee, cert), serverHsTraffic, 0),
                this.encryptHandshakeRecord(concatBytes(cv, fin), serverHsTraffic, 1),
            ];
        } else {
            encrypted = [];
            let seq = 0;
            for (const msg of [ee, cert, cv, fin]) {
                encrypted.push(this.encryptHandshakeRecord(msg, serverHsTraffic, seq));
                seq++;
            }
        }

        this.responses = [shRecord, ...encrypted];
        // Reference unused values to satisfy strict linters under esbuild.
        void clientTrafficSecret;
    }
}
