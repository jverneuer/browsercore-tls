/**
 * TLS 1.3 server-flight message handling.
 *
 * Decodes the server's encrypted second flight — EncryptedExtensions, Certificate,
 * CertificateVerify, Finished — and produces the client's Finished in reply. Each
 * function is a pure transformation over its inputs (the message bytes plus the
 * slice of connection state it needs); the connection class owns the state and
 * threads it through. This keeps the message-layout logic isolated from the
 * record layer and the handshake state machine.
 */

import type { CryptoProvider, HashId } from "@browsercore/crypto";
import type { Transport } from "@browsercore/transport";
import type { TrafficSecrets } from "../types.js";
import { TlsHandshakeError } from "../errors.js";
import { ExtensionType, findExtension, parseExtensions } from "../extensions/extensions.js";
import { hkdfExpandLabel, hashLengthFor } from "../crypto/keySchedule.js";
import { ContentType, decryptRecord, type encryptRecord, readContentType } from "../record/record.js";
import { parseCertificate, validateHostname, verifyChain, type Certificate, type CertificateChain, type TrustAnchor } from "../certificates/certificates.js";
import { transcriptHash } from "./key-exchange.js";
import { readHeaderBytes as readHeaderBytesFromRecord, readRawRecord as readRawRecordFromRecord, xorNonce } from "./record-layer.js";

/** Extract the negotiated ALPN protocol from EncryptedExtensions, if any. */
export function parseAlpnFromEncryptedExtensions(body: Uint8Array): string | undefined {
    const extensions = parseExtensions(body);
    const alpn = findExtension(extensions, ExtensionType.APPLICATION_LAYER_PROTOCOL_NEGOTIATION);
    if (alpn === undefined) {
        return undefined;
    }
    // Server ALPN body: length-prefixed list with a single entry.
    if (alpn.data.length < 3) {
        return undefined;
    }
    const nameLen = alpn.data[2];
    if (nameLen === undefined || 3 + nameLen > alpn.data.length) {
        return undefined;
    }
    return new TextDecoder().decode(alpn.data.subarray(3, 3 + nameLen));
}

/**
 * Parse a Certificate handshake message (RFC 8446 §4.4.2) into a chain. The body
 * is: certificate_request_context (length-prefixed, len 1) then a length-prefixed
 * list of CertificateEntry { cert_data, extensions }.
 */
export function parseCertificateMessage(body: Uint8Array): CertificateChain {
    let o = 0;
    const readByte = (): number => {
        const byte = body[o];
        if (byte === undefined) {
            throw new TlsHandshakeError("certificate", {
                cause: new Error(`certificate message byte truncated at offset ${o}`),
            });
        }
        o++;
        return byte;
    };
    const ctxLen = readByte();
    o += ctxLen;
    const listLen = (readByte() << 16) | (readByte() << 8) | readByte();
    const listEnd = o + listLen;
    if (listEnd > body.length) {
        throw new TlsHandshakeError("certificate", {
            cause: new Error("certificate_list length exceeds message body"),
        });
    }
    const certs: Certificate[] = [];
    while (o < listEnd) {
        const certLen = (readByte() << 16) | (readByte() << 8) | readByte();
        const certDer = body.subarray(o, o + certLen);
        o += certLen;
        const extLen = (readByte() << 8) | readByte();
        o += extLen;
        certs.push(parseCertificate(certDer));
    }
    if (certs.length === 0) {
        throw new TlsHandshakeError("certificate", {
            cause: new Error("server sent an empty certificate_list"),
        });
    }
    // certs.length >= 1 guarantees both indices are in bounds.
    const leaf = certs[0];
    const root = certs.at(-1);
    if (leaf === undefined || root === undefined) {
        throw new TlsHandshakeError("certificate", {
            cause: new Error("certificate list missing leaf or root"),
        });
    }
    const intermediates = certs.slice(1, certs.length - 1);
    return { leaf, intermediates, root };
}

/**
 * Validate the Certificate message: hostname check against the leaf, then full
 * chain verification when trust anchors are available. Returns the parsed chain.
 *
 * `now` (epoch seconds) is injected rather than read from the clock, so this
 * helper is pure and testable — the connection supplies the current time, never
 * the validation logic itself.
 */
export async function validateCertificateChain(
    body: Uint8Array,
    serverName: string,
    trustAnchors: readonly Uint8Array[],
    now: number,
    provider: CryptoProvider,
): Promise<CertificateChain> {
    const chain = parseCertificateMessage(body);
    if (!validateHostname(chain.leaf, serverName)) {
        throw new TlsHandshakeError("certificate", {
            cause: new Error(`hostname "${serverName}" does not match the leaf certificate`),
        });
    }
    // Full chain verification requires trust anchors. Without them we still
    // performed hostname validation above; chain verification is best-effort.
    if (trustAnchors.length > 0) {
        // Trust anchors arrive as raw DER root certificates; verifyChain wants
        // parsed TrustAnchor records (SPKI + subject). A trust anchor is a
        // self-signed root, so its issuer DN is also its subject.
        const anchors = trustAnchors.map((der): TrustAnchor => {
            const root = parseCertificate(der);
            return { subjectPublicKeyInfo: root.subjectPublicKeyInfo, subject: root.issuer };
        });
        await verifyChain(chain, anchors, serverName, now, provider);
    }
    return chain;
}

/** Build the client Finished message bytes under the client handshake traffic key. */
export function buildClientFinishedMessage(
    hash: HashId,
    clientHsTrafficSecret: Uint8Array,
    transcript: readonly Uint8Array[],
    provider: CryptoProvider,
): Uint8Array {
    const hashLen = hashLengthFor(hash);
    const finishedKey = hkdfExpandLabel(clientHsTrafficSecret, "finished", new Uint8Array(0), hashLen, hash, provider);
    const verifyData = provider.hmac(hash, finishedKey, transcriptHash(transcript, hash, provider))
    const message = new Uint8Array(4 + verifyData.length);
    message[0] = 20; // HandshakeType.FINISHED
    message[1] = (verifyData.length >> 16) & 0xff;
    message[2] = (verifyData.length >> 8) & 0xff;
    message[3] = verifyData.length & 0xff;
    message.set(verifyData, 4);
    return message;
}

/**
 * Split a decrypted record's content into individual handshake messages.
 *
 * RFC 8446 §5.1 permits a server to coalesce multiple handshake messages into a
 * single TLSCiphertext record. Each message is framed as type(1) || length(3)
 * || body (24-bit length in bytes 1..3), so the content can be split
 * deterministically by walking the framing.
 *
 * When the content holds exactly one message (the non-coalesced case), this
 * returns a single-element array containing the original content unchanged.
 *
 * @param content  The full decrypted record content (inner content type byte
 *                 and trailing zero-padding already stripped by the caller).
 */
export function splitHandshakeMessages(content: Uint8Array): Uint8Array[] {
    const messages: Uint8Array[] = [];
    let offset = 0;
    while (offset < content.length) {
        if (offset + 4 > content.length) {
            throw new TlsHandshakeError("finished", {
                cause: new Error("truncated handshake message header in coalesced record"),
            });
        }
        // 24-bit body length in bytes 1..3 (byte 0 is the handshake type).
        const b1 = content[offset + 1];
        const b2 = content[offset + 2];
        const b3 = content[offset + 3];
        if (b1 === undefined || b2 === undefined || b3 === undefined) {
            throw new TlsHandshakeError("finished", {
                cause: new Error("truncated handshake message header in coalesced record"),
            });
        }
        const bodyLen = (b1 << 16) | (b2 << 8) | b3;
        const totalLen = 4 + bodyLen;
        if (offset + totalLen > content.length) {
            throw new TlsHandshakeError("finished", {
                cause: new Error("handshake message body exceeds record content boundary"),
            });
        }
        messages.push(content.subarray(offset, offset + totalLen));
        offset += totalLen;
    }
    return messages;
}

/**
 * Read one encrypted handshake message, decrypting and stripping the inner type.
 * Returns the whole handshake message (header + body), the body alone, and the
 * buffer left after consuming the record.
 *
 * When the record contains multiple coalesced handshake messages (RFC 8446
 * §5.1), `whole` holds the concatenation of all messages and the caller must
 * use {@link splitHandshakeMessages} to separate them.
 */
export async function readEncryptedHandshakeMessage(
    readBuffer: Uint8Array,
    transport: Transport,
    aead: Parameters<typeof encryptRecord>[4],
    traffic: TrafficSecrets,
    seq: number,
    provider: CryptoProvider,
): Promise<{ whole: Uint8Array; body: Uint8Array; readBuffer: Uint8Array }> {
    // RFC 8446 §5: a TLS 1.3 server may send a single change_cipher_spec record
    // (content type 20) between ServerHello and the encrypted flight for
    // middlebox compatibility. Clients MUST silently ignore it. CCS records are
    // unencrypted and pre-handshake, so they do NOT advance the AEAD sequence
    // number — only the real encrypted record that follows consumes `seq`.
    let header = await readHeaderBytesFromRecord(readBuffer, transport);
    let record = await readRawRecordFromRecord(header.readBuffer, transport, header);
    while (record.type === ContentType.CHANGE_CIPHER_SPEC) {
        // Sequential by necessity: each read consumes a prefix of readBuffer and
        // returns the remainder, so the next read must wait for it. The loop
        // continuation (record.type) is also re-evaluated after every read.
        // eslint-disable-next-line no-await-in-loop
        header = await readHeaderBytesFromRecord(record.readBuffer, transport);
        // eslint-disable-next-line no-await-in-loop
        record = await readRawRecordFromRecord(header.readBuffer, transport, header);
    }
    if (record.type !== ContentType.APPLICATION_DATA) {
        throw new TlsHandshakeError("finished", {
            cause: new Error(`expected encrypted APPLICATION_DATA record, got ${record.type}`),
        });
    }
    const nonce = xorNonce(traffic.iv, seq);
    const plaintext = decryptRecord(record.fragment, traffic.key, nonce, header.raw, aead, provider);
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
            cause: new Error("encrypted handshake plaintext ended before the inner content type byte"),
        });
    }
    const innerType = readContentType(innerTypeByte);
    const content = plaintext.subarray(0, end - 1);
    if (innerType !== ContentType.HANDSHAKE) {
        throw new TlsHandshakeError("finished", {
            cause: new Error(`expected inner handshake type, got ${innerType}`),
        });
    }
    // `content` is the full handshake message (4-byte header + body).
    return { whole: content, body: content.subarray(4), readBuffer: record.readBuffer };
}
