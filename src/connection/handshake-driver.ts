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

import type { StreamTransport } from "@browsercore/transport";
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
import { defaultRandomByte } from "../handshake/client-hello.js";
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
    readonly transport: StreamTransport;
    /** Cryptographic provider (defaults to the @browsercore/crypto singleton). */
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
    const clientHello = buildClientHello(profile, keyPairs, defaultRandomByte, ctx.crypto);
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
    writeEncryptedRecord(
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
 */
async function consumeServerFlight(
    ctx: HandshakeContext,
    serverName: string,
    trustAnchors: readonly Uint8Array[],
    now: number,
): Promise<void> {
    let phase: HandshakePhase = recordServerHello({ phase: "client_hello_sent" }, ctx.serverHello);

    // EncryptedExtensions.
    let message = await readEncryptedHandshakeMessage(
        ctx.readBuffer, ctx.transport, ctx.aead, ctx.serverHsTraffic, ctx.serverHsSeq,
    ctx.crypto,
    );
    ctx.readBuffer = message.readBuffer;
    ctx.serverHsSeq++;
    phase = advanceHandshake(phase, HandshakeType.ENCRYPTED_EXTENSIONS);
    ctx.transcript.push(message.whole);
    const alpn = parseAlpnFromEncryptedExtensions(message.body);
    if (alpn !== undefined) {
        ctx.alpnProtocol = alpn;
    }

    // Certificate.
    message = await readEncryptedHandshakeMessage(
        ctx.readBuffer, ctx.transport, ctx.aead, ctx.serverHsTraffic, ctx.serverHsSeq,
    ctx.crypto,
    );
    ctx.readBuffer = message.readBuffer;
    ctx.serverHsSeq++;
    phase = advanceHandshake(phase, HandshakeType.CERTIFICATE);
    ctx.transcript.push(message.whole);
    const chain = await validateCertificateChain(message.body, serverName, trustAnchors, now);
    ctx.peerCertificate = chain.leaf;

    // CertificateVerify.
    message = await readEncryptedHandshakeMessage(
        ctx.readBuffer, ctx.transport, ctx.aead, ctx.serverHsTraffic, ctx.serverHsSeq,
    ctx.crypto,
    );
    ctx.readBuffer = message.readBuffer;
    ctx.serverHsSeq++;
    phase = advanceHandshake(phase, HandshakeType.CERTIFICATE_VERIFY);
    ctx.transcript.push(message.whole);

    // Finished — verify against the transcript *before* appending the Finished.
    const finishedTranscript = transcriptHash(ctx.transcript, ctx.hash);
    message = await readEncryptedHandshakeMessage(
        ctx.readBuffer, ctx.transport, ctx.aead, ctx.serverHsTraffic, ctx.serverHsSeq,
    ctx.crypto,
    );
    ctx.readBuffer = message.readBuffer;
    ctx.serverHsSeq++;
    verifyServerFinished(message.body, finishedTranscript, ctx.hash, ctx.serverHsTrafficSecret);
    advanceHandshake(phase, HandshakeType.FINISHED);
    ctx.transcript.push(message.whole);
}
