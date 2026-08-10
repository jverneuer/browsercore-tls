/**
 * TLS 1.3 handshake driver (RFC 8446).
 *
 * The connection class owns its mutable state (read buffer, transcript, traffic
 * secrets, sequence counters); this module owns the *sequence* of the handshake
 * — what to send, what to read next, when to derive which secret, when to verify
 * the Finished. It operates through a {@link HandshakeContext} the connection
 * implements, so it can read and write that state without the connection class
 * having to carry the handshake choreography inline.
 *
 * Splitting the driver out of `tls.ts` keeps the public class focused on its API
 * surface (read/write/close/on) and the lifecycle of its fields, while every
 * byte-level handshake step lives here and stays independently readable.
 */

import type { Transport } from "@browsercore/transport";
import type { CryptoProvider, HashId } from "@browsercore/crypto";
import { TlsHandshakeError } from "../errors.js";
import { ContentType, cipherSuiteToAead } from "../record/record.js";
import {
    advanceHandshake,
    buildClientHello,
    parseServerHello,
    recordServerHello,
    HandshakeType,
    type HandshakePhase,
    type ServerHello,
} from "../handshake/handshake.js";
import {
    deriveApplicationSecrets,
    deriveHandshakeTrafficSecrets,
    deriveTrafficSecrets,
    hashFor,
} from "../crypto/keySchedule.js";
import type {
    AeadAlgorithm,
    ApplicationTrafficSecrets,
    CipherSuite,
    ClientHelloConfig,
    KeyPair,
    TrafficSecrets,
} from "../types.js";
// `Certificate` is derived from the chain `validateCertificateChain` returns, so
// we don't take a direct dependency on certificates.js here (keeps this module's
// dependency list under the lint budget without sacrificing type precision).
type ValidatedCertificate = Awaited<ReturnType<typeof validateCertificateChain>>["leaf"];
// Import from the individual submodules (not the ./index.js barrel) to avoid a
// dependency cycle: index.ts re-exports this module, so reaching back through
// it would close the loop. The submodules are the real owners of these helpers.
import { computeSharedSecret, transcriptHash, verifyServerFinished } from "./key-exchange.js";
import {
    buildClientFinishedMessage,
    parseAlpnFromEncryptedExtensions,
    readEncryptedHandshakeMessage,
    splitHandshakeMessages,
    validateCertificateChain,
} from "./handshake-messages.js";
import {
    readHeaderBytes,
    readRawRecord,
    writeEncryptedRecord,
    writeRecord,
} from "./record-layer.js";

/**
 * The slice of connection state the handshake driver reads and mutates.
 * The connection implements this; the driver never reaches past these fields.
 */
export interface HandshakeContext {
    readonly transport: Transport;
    /** Cryptographic provider, injected by the owning connection (no default). */
    crypto: CryptoProvider;
    /** Mutable: buffered bytes not yet consumed by the record framer. */
    readBuffer: Uint8Array;
    /** Mutable: running transcript of full handshake messages. */
    readonly transcript: Uint8Array[];
    /** Mutable: negotiated cipher suite + derived AEAD/hash/transcript params. */
    cipherSuite: CipherSuite;
    aead: AeadAlgorithm;
    hash: HashId;
    serverHello: ServerHello;
    /** Mutable: handshake traffic secrets (per direction) and the raw secrets. */
    clientHsTraffic: TrafficSecrets;
    serverHsTraffic: TrafficSecrets;
    clientHsTrafficSecret: Uint8Array;
    serverHsTrafficSecret: Uint8Array;
    masterSecret: Uint8Array;
    /** Mutable: handshake-direction sequence counters. */
    clientHsSeq: number;
    serverHsSeq: number;
    /** Set when the server negotiates ALPN in EncryptedExtensions. */
    alpnProtocol?: string | undefined;
    /** Set to the validated leaf once the Certificate message is consumed. */
    peerCertificate?: ValidatedCertificate | undefined;
}

/** Constant: the only key-share group the crypto backend can generate. */
const SUPPORTED_GROUP = "x25519";

/** Apply the result of {@link parseServerHello} to the context's fields. */
function applyNegotiation(ctx: HandshakeContext): void {
    ctx.aead = cipherSuiteToAead(ctx.cipherSuite);
    ctx.hash = hashFor(ctx.cipherSuite);
}

/**
 * Drive the TLS 1.3 handshake to completion against `ctx`.
 *
 * `now` (epoch seconds) is injected by the caller — the orchestrator reads the
 * clock once so this driver (and the certificate validation it invokes) stays
 * pure and testable.
 */
export async function runHandshake(
    ctx: HandshakeContext,
    profile: ClientHelloConfig,
    serverName: string,
    trustAnchors: readonly Uint8Array[],
    generateKeyShares: (groups: readonly string[]) => Promise<KeyPair[]>,
    now: number,
): Promise<ApplicationTrafficSecrets> {
    // TLS 1.3 only: reject a profile that cannot negotiate TLS 1.3.
    if (!profile.supportedVersions.some((v) => v.name === "TLS 1.3")) {
        throw new TlsHandshakeError("client_hello", {
            cause: new Error("TLS 1.2-only handshakes are not supported by this client"),
        });
    }

    // 1. Generate key shares for the groups the crypto backend supports.
    const desired = profile.keyShareGroups.filter((g) => g === SUPPORTED_GROUP);
    if (desired.length === 0) {
        throw new TlsHandshakeError("client_hello", {
            cause: new Error("no supported key share groups in the selected profile"),
        });
    }
    const keyPairs = await generateKeyShares(desired);

    // 2. Build and send the ClientHello as a plaintext handshake record.
    const clientHello = buildClientHello(profile, keyPairs, () => {
        const byte = ctx.crypto.randomBytes(1)[0];
        return byte === undefined ? 0 : byte / 256;
    }, ctx.crypto);
    ctx.transcript.push(clientHello);
    await writeRecord(ctx.transport, ContentType.HANDSHAKE, clientHello);

    // 3. Read the ServerHello (still plaintext) and validate the negotiation.
    const shHeader = await readHeaderBytes(ctx.readBuffer, ctx.transport);
    ctx.readBuffer = shHeader.readBuffer;
    const shRecord = await readRawRecord(ctx.readBuffer, ctx.transport, shHeader);
    ctx.readBuffer = shRecord.readBuffer;
    if (shRecord.type !== ContentType.HANDSHAKE) {
        throw new TlsHandshakeError("server_hello", {
            cause: new Error(`expected handshake record, got content type ${shRecord.type}`),
        });
    }
    ctx.transcript.push(shRecord.fragment);
    const serverHello = parseServerHello(shRecord.fragment.subarray(4), {
        cipherSuites: profile.cipherSuites,
        supportedVersions: profile.supportedVersions,
    });
    ctx.serverHello = serverHello;
    ctx.cipherSuite = serverHello.cipherSuite;
    applyNegotiation(ctx);

    // 4. (EC)DHE key exchange.
    const sharedSecret = computeSharedSecret(serverHello, keyPairs, ctx.crypto)

    // 5. Derive handshake traffic secrets from the ClientHello..ServerHello transcript.
    const helloTranscript = transcriptHash(ctx.transcript, ctx.hash, ctx.crypto)
    const { masterSecret, clientTrafficSecret, serverTrafficSecret } = deriveHandshakeTrafficSecrets(
        sharedSecret,
        helloTranscript,
        ctx.cipherSuite,
        ctx.crypto,
    );
    ctx.masterSecret = masterSecret;
    ctx.clientHsTrafficSecret = clientTrafficSecret;
    ctx.serverHsTrafficSecret = serverTrafficSecret;
    ctx.clientHsTraffic = deriveTrafficSecrets(clientTrafficSecret, ctx.cipherSuite, ctx.hash, ctx.crypto)
    ctx.serverHsTraffic = deriveTrafficSecrets(serverTrafficSecret, ctx.cipherSuite, ctx.hash, ctx.crypto)

    // 6. Consume the server's encrypted flight.
    await consumeServerFlight(ctx, serverName, trustAnchors, now);

    // 7. Derive application traffic secrets from the full transcript.
    const handshakeTranscript = transcriptHash(ctx.transcript, ctx.hash, ctx.crypto)
    const applicationSecrets = deriveApplicationSecrets(ctx.masterSecret, handshakeTranscript, ctx.cipherSuite, ctx.crypto)

    // 8. Send the client Finished under the client handshake traffic key.
    const finishedMessage = buildClientFinishedMessage(ctx.hash, ctx.clientHsTrafficSecret, ctx.transcript, ctx.crypto)
    await writeEncryptedRecord(
        ctx.transport,
        ctx.aead,
        ctx.clientHsTraffic,
        ContentType.HANDSHAKE,
        finishedMessage,
        ctx.clientHsSeq,
        ctx.crypto,
    );
    ctx.clientHsSeq++;

    return applicationSecrets;
}

/**
 * Read the server's encrypted second flight message-by-message, advancing the
 * handshake state machine and updating the transcript. Server Finished is
 * verified against the transcript as it stood *before* the Finished message.
 *
 * RFC 8446 §5.1 permits a server to coalesce multiple handshake messages into a
 * single encrypted record. This function buffers messages from a decrypted
 * record and only reads + decrypts the next record when the buffer is drained,
 * so it works correctly whether the server sends one message per record (the
 * simple case) or packs the entire flight into a single record (the common case
 * for real TLS 1.3 servers like Cloudflare, nginx, and OpenSSL).
 */
async function consumeServerFlight(
    ctx: HandshakeContext,
    serverName: string,
    trustAnchors: readonly Uint8Array[],
    now: number,
): Promise<void> {
    let phase: HandshakePhase = recordServerHello({ phase: "client_hello_sent" }, ctx.serverHello);

    // Messages parsed from the current record but not yet consumed. The AEAD
    // sequence number advances once per RECORD (not per message), because all
    // messages in a coalesced record share the same nonce — so we only
    // increment serverHsSeq when actually reading a new record.
    let pendingMessages: Uint8Array[] = [];

    /**
     * Return the next handshake message from the server, reading and decrypting
     * a new record only when no buffered messages remain. This decouples
     * "give me the next handshake message" (what the driver needs) from "read
     * the next record" (the record-layer operation), bridging the gap that
     * caused the coalesced-record stall.
     */
    async function nextHandshakeMessage(): Promise<{ whole: Uint8Array; body: Uint8Array }> {
        if (pendingMessages.length > 0) {
            const msg = pendingMessages.shift();
            if (msg === undefined) {
                // Length was just checked; this is unreachable but satisfies
                // noUncheckedIndexedAccess without a non-null assertion.
                throw new TlsHandshakeError("finished", {
                    cause: new Error("pending message queue emptied between check and shift"),
                });
            }
            return { whole: msg, body: msg.subarray(4) };
        }
        const result = await readEncryptedHandshakeMessage(
            ctx.readBuffer, ctx.transport, ctx.aead, ctx.serverHsTraffic, ctx.serverHsSeq,
            ctx.crypto,
        );
        ctx.readBuffer = result.readBuffer;
        ctx.serverHsSeq++;
        const messages = splitHandshakeMessages(result.whole);
        const first = messages.shift();
        if (first === undefined) {
            throw new TlsHandshakeError("finished", {
                cause: new Error("decrypted record contained no handshake messages"),
            });
        }
        pendingMessages = messages;
        return { whole: first, body: first.subarray(4) };
    }

    // EncryptedExtensions.
    let message = await nextHandshakeMessage();
    phase = advanceHandshake(phase, HandshakeType.ENCRYPTED_EXTENSIONS);
    ctx.transcript.push(message.whole);
    const alpn = parseAlpnFromEncryptedExtensions(message.body);
    if (alpn !== undefined) {
        ctx.alpnProtocol = alpn;
    }

    // Certificate.
    message = await nextHandshakeMessage();
    phase = advanceHandshake(phase, HandshakeType.CERTIFICATE);
    ctx.transcript.push(message.whole);
    const chain = await validateCertificateChain(message.body, serverName, trustAnchors, now, ctx.crypto);
    ctx.peerCertificate = chain.leaf;

    // CertificateVerify.
    message = await nextHandshakeMessage();
    phase = advanceHandshake(phase, HandshakeType.CERTIFICATE_VERIFY);
    ctx.transcript.push(message.whole);

    // Finished — verify against the transcript *before* appending the Finished.
    const finishedTranscript = transcriptHash(ctx.transcript, ctx.hash, ctx.crypto);
    message = await nextHandshakeMessage();
    verifyServerFinished(message.body, finishedTranscript, ctx.hash, ctx.serverHsTrafficSecret, ctx.crypto);
    advanceHandshake(phase, HandshakeType.FINISHED);
    ctx.transcript.push(message.whole);
}
