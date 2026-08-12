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
import { TlsHandshakeError, type AlertLevel, type HandshakePhase as TimeoutPhase } from "../errors.js";
import { ContentType, cipherSuiteToAead } from "../record/record.js";
import {
    advanceHandshake,
    buildClientHello,
    parseServerHello,
    recordServerHello,
    HandshakeType,
    isHelloRetryRequest,
    parseHelloRetryRequestExtensions,
    buildMessageHashMessage,
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
    verifyCertificateVerify,
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
    /**
     * Mutable: raw application traffic secrets, set when the driver derives
     * application secrets (step 7). Retained so the connection can rotate keys
     * via {@link updateTrafficSecrets} on KeyUpdate (RFC 8446 §4.6.3).
     */
    clientAppSecret: Uint8Array;
    serverAppSecret: Uint8Array;
    /** Mutable: handshake-direction sequence counters. */
    clientHsSeq: number;
    serverHsSeq: number;
    /** True once the handshake traffic secrets have been derived (sendAlert gate). */
    hsTrafficReady: boolean;
    /** Set when the server negotiates ALPN in EncryptedExtensions. */
    alpnProtocol?: string | undefined;
    /** Set to the validated leaf once the Certificate message is consumed. */
    peerCertificate?: ValidatedCertificate | undefined;
    /**
     * Mutable: the handshake phase currently in progress. Updated by the driver
     * before each step so {@link withTimeout} can report the true stall location
     * in its error message instead of a hardcoded guess.
     */
    currentPhase: TimeoutPhase;
    /**
     * Optional debug trace callback. When set, the driver and record layer emit
     * a line before/after each I/O and crypto step. This is the primary
     * diagnostic tool for pinpointing handshake stalls.
     */
    onDebug: ((msg: string) => void) | undefined;
    /**
     * Send a TLS alert (RFC 8446 §6) to the peer. Best-effort: if the traffic
     * keys are not yet derived (early handshake failure) or the transport write
     * fails, the alert is silently dropped. The connection's error-cleanup path
     * (transport close) is the fallback.
     */
    sendAlert(level: AlertLevel, description: number): Promise<void>;
}

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
    ctx.currentPhase = "init";

    // TLS 1.3 only: reject a profile that cannot negotiate TLS 1.3.
    if (!profile.supportedVersions.some((v) => v.name === "TLS 1.3")) {
        throw new TlsHandshakeError("client_hello", {
            cause: new Error("TLS 1.2-only handshakes are not supported by this client"),
        });
    }

    // 1. Generate key shares for ALL groups the profile offers — including
    // post-quantum hybrids (X25519MLKEM768). The crypto backend generates an
    // X25519 key tagged with the hybrid name so the key_share extension emits
    // the correct group ID. Multiple key shares are mandatory for matching real
    // browser fingerprints (Chrome offers x25519, secp256r1, secp384r1, and
    // X25519MLKEM768 simultaneously).
    ctx.currentPhase = "client_hello";
    ctx.onDebug?.("phase: client_hello — generating key shares");
    const keyPairs = await generateKeyShares(profile.keyShareGroups);
    if (keyPairs.length === 0) {
        throw new TlsHandshakeError("client_hello", {
            cause: new Error("no supported key share groups in the selected profile"),
        });
    }

    // 2. Build and send the ClientHello as a plaintext handshake record.
    ctx.onDebug?.("phase: client_hello — building and sending ClientHello");
    const greaseRandom = (): number => {
        const byte = ctx.crypto.randomBytes(1)[0];
        return byte === undefined ? 0 : byte / 256;
    };
    const clientHello = buildClientHello(profile, keyPairs, greaseRandom, ctx.crypto);
    ctx.transcript.push(clientHello);
    await writeRecord(ctx.transport, ContentType.HANDSHAKE, clientHello);
    ctx.onDebug?.(`phase: client_hello — ClientHello sent (${clientHello.length} bytes)`);

    // 3. Read the ServerHello (still plaintext) and validate the negotiation.
    ctx.currentPhase = "server_hello";
    ctx.onDebug?.("phase: server_hello — waiting for ServerHello record");
    const shHeader = await readHeaderBytes(ctx.readBuffer, ctx.transport, ctx.onDebug);
    ctx.readBuffer = shHeader.readBuffer;
    const shRecord = await readRawRecord(ctx.readBuffer, ctx.transport, shHeader, ctx.onDebug);
    ctx.readBuffer = shRecord.readBuffer;
    if (shRecord.type !== ContentType.HANDSHAKE) {
        // Parse Alert to show the server's rejection reason
        if (shRecord.type === 21 && shRecord.fragment.length >= 2) {
            const alertLevel = shRecord.fragment[0]; // 1=warning, 2=fatal
            const alertDesc = shRecord.fragment[1];  // RFC 8446 §6
            const alertNames: Record<number, string> = {
                0: "close_notify", 10: "unexpected_message", 20: "bad_record_mac",
                40: "handshake_failure", 41: "bad_certificate", 43: "unsupported_certificate",
                44: "certificate_revoked", 45: "certificate_expired", 47: "illegal_parameter",
                48: "unknown_ca", 49: "access_denied", 50: "decode_error", 51: "decrypt_error",
                70: "protocol_version", 71: "insufficient_security", 80: "internal_error",
                86: "inappropriate_fallback", 90: "user_canceled", 100: "missing_extension",
                109: "missing_extension", 110: "unsupported_extension", 111: "certificate_unobtainable",
                112: "unrecognized_name", 113: "bad_certificate_status_response",
                114: "unknown_psk_identity", 115: "certificate_required",
            };
            const levelStr = alertLevel === 2 ? "fatal" : alertLevel === 1 ? "warning" : `level=${alertLevel}`;
            const descStr = alertDesc === undefined ? "unknown" : (alertNames[alertDesc] ?? `unknown(${alertDesc})`);
            throw new TlsHandshakeError("server_hello", {
                cause: new Error(
                    `server sent TLS Alert: ${levelStr} ${descStr} (${alertDesc}). ` +
                    `The server rejected our ClientHello.`,
                ),
            });
        }
        throw new TlsHandshakeError("server_hello", {
            cause: new Error(`expected handshake record, got content type ${shRecord.type}`),
        });
    }
    ctx.transcript.push(shRecord.fragment);
    const firstHello = parseServerHello(shRecord.fragment.subarray(4), {
        cipherSuites: profile.cipherSuites,
        supportedVersions: profile.supportedVersions,
    });

    // Set cipher suite + hash early — the HRR carries the same cipher suite as
    // the real ServerHello will, and we need ctx.hash to compute the synthetic
    // message_hash transcript prefix during HRR handling.
    ctx.cipherSuite = firstHello.cipherSuite;
    applyNegotiation(ctx);

    // HelloRetryRequest detection (RFC 8446 §4.1.3). The server sends an HRR
    // (a special ServerHello with the sentinel random) when the client's initial
    // key-share group is unacceptable. The client must rewrite the transcript,
    // generate a fresh key share, resend the ClientHello, and read the *real*
    // ServerHello that follows.
    let effectiveKeyPairs = keyPairs;
    let serverHello = firstHello;

    if (isHelloRetryRequest(firstHello.random)) {
        ctx.onDebug?.("phase: server_hello — HelloRetryRequest detected");

        // Transcript rewrite (RFC 8446 §4.4.1): replace ClientHello_1 + HRR
        // with message_hash(Hash(ClientHello_1)) + HRR.
        ctx.transcript.pop(); // remove HRR
        ctx.transcript.pop(); // remove ClientHello_1
        const ch1Hash = transcriptHash([clientHello], ctx.hash, ctx.crypto);
        ctx.transcript.push(buildMessageHashMessage(ch1Hash), shRecord.fragment);

        // Parse HRR extensions: selected_group + optional cookie.
        const hrr = parseHelloRetryRequestExtensions(firstHello.extensions);
        ctx.onDebug?.(`phase: server_hello — HRR requests group ${hrr.selectedGroup}${hrr.cookie === undefined ? "" : " with cookie"}`);

        // Generate a fresh key share for the server's selected group.
        effectiveKeyPairs = await generateKeyShares([hrr.selectedGroup]);

        // Build and send ClientHello_2 with the new key share and the echoed cookie.
        const clientHello2 = hrr.cookie === undefined
            ? buildClientHello(profile, effectiveKeyPairs, greaseRandom, ctx.crypto)
            : buildClientHello(profile, effectiveKeyPairs, greaseRandom, ctx.crypto, hrr.cookie);
        ctx.transcript.push(clientHello2);
        await writeRecord(ctx.transport, ContentType.HANDSHAKE, clientHello2);
        ctx.onDebug?.(`phase: server_hello — ClientHello_2 sent after HRR (${clientHello2.length} bytes)`);

        // Read the *real* ServerHello.
        ctx.onDebug?.("phase: server_hello — waiting for real ServerHello after HRR");
        const realShHeader = await readHeaderBytes(ctx.readBuffer, ctx.transport, ctx.onDebug);
        ctx.readBuffer = realShHeader.readBuffer;
        const realShRecord = await readRawRecord(ctx.readBuffer, ctx.transport, realShHeader, ctx.onDebug);
        ctx.readBuffer = realShRecord.readBuffer;
        if (realShRecord.type !== ContentType.HANDSHAKE) {
            throw new TlsHandshakeError("server_hello", {
                cause: new Error(`expected handshake record after HRR, got content type ${realShRecord.type}`),
            });
        }
        ctx.transcript.push(realShRecord.fragment);
        serverHello = parseServerHello(realShRecord.fragment.subarray(4), {
            cipherSuites: profile.cipherSuites,
            supportedVersions: profile.supportedVersions,
        });
        // The real ServerHello is authoritative for the cipher suite (though it
        // must match the HRR — the server cannot change suites mid-handshake).
        ctx.cipherSuite = serverHello.cipherSuite;
        applyNegotiation(ctx);
    }

    ctx.onDebug?.(`phase: server_hello — parsed ServerHello (cipher=${serverHello.cipherSuite}, version=${serverHello.selectedVersion.name})`);
    ctx.serverHello = serverHello;

    // 4. (EC)DHE key exchange.
    ctx.currentPhase = "key_exchange";
    ctx.onDebug?.("phase: key_exchange — computing shared secret");
    const sharedSecret = computeSharedSecret(serverHello, effectiveKeyPairs, ctx.crypto)
    ctx.onDebug?.("phase: key_exchange — shared secret computed");

    // 5. Derive handshake traffic secrets from the ClientHello..ServerHello transcript.
    ctx.onDebug?.("phase: key_exchange — deriving handshake traffic secrets");
    const helloTranscript = transcriptHash(ctx.transcript, ctx.hash, ctx.crypto)
    const { masterSecret, clientTrafficSecret, serverTrafficSecret } = deriveHandshakeTrafficSecrets(
        sharedSecret,
        helloTranscript,
        ctx.cipherSuite,
        ctx.crypto,
    );
    ctx.onDebug?.("phase: key_exchange — handshake traffic secrets derived");
    ctx.masterSecret = masterSecret;
    ctx.clientHsTrafficSecret = clientTrafficSecret;
    ctx.serverHsTrafficSecret = serverTrafficSecret;
    ctx.clientHsTraffic = deriveTrafficSecrets(clientTrafficSecret, ctx.cipherSuite, ctx.hash, ctx.crypto)
    ctx.serverHsTraffic = deriveTrafficSecrets(serverTrafficSecret, ctx.cipherSuite, ctx.hash, ctx.crypto)
    ctx.hsTrafficReady = true;

    // 6. Consume the server's encrypted flight.
    await consumeServerFlight(ctx, serverName, trustAnchors, now);

    // 7. Derive application traffic secrets from the full transcript.
    ctx.currentPhase = "client_finished";
    ctx.onDebug?.("phase: client_finished — deriving application traffic secrets");
    const handshakeTranscript = transcriptHash(ctx.transcript, ctx.hash, ctx.crypto)
    const applicationSecrets = deriveApplicationSecrets(ctx.masterSecret, handshakeTranscript, ctx.cipherSuite, ctx.crypto)
    ctx.clientAppSecret = applicationSecrets.clientSecret;
    ctx.serverAppSecret = applicationSecrets.serverSecret;
    ctx.onDebug?.("phase: client_finished — application traffic secrets derived");

    // 8. Send the client Finished under the client handshake traffic key.
    ctx.onDebug?.("phase: client_finished — building and sending client Finished");
    const finishedMessage = buildClientFinishedMessage(ctx.hash, ctx.clientHsTrafficSecret, ctx.transcript, ctx.crypto)
    await writeEncryptedRecord(
        ctx.transport,
        ctx.aead,
        ctx.clientHsTraffic,
        ContentType.HANDSHAKE,
        finishedMessage,
        ctx.clientHsSeq,
        ctx.crypto,
        ctx.onDebug,
    );
    ctx.clientHsSeq++;
    // Record the client Finished in the transcript. The resumption_master_secret
    // (RFC 8446 §7.5) is Derive-Secret(master_secret, "res master",
    // Transcript-Hash(ClientHello..client Finished)) — so the transcript MUST
    // include it for post-handshake NewSessionTicket processing.
    ctx.transcript.push(finishedMessage);
    ctx.onDebug?.("phase: client_finished — client Finished sent");

    ctx.currentPhase = "application";
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
                throw new TlsHandshakeError("encrypted_extensions", {
                    cause: new Error("pending message queue emptied between check and shift"),
                });
            }
            return { whole: msg, body: msg.subarray(4) };
        }
        ctx.onDebug?.(`consumeServerFlight: reading encrypted record, seq=${ctx.serverHsSeq}`);
        const result = await readEncryptedHandshakeMessage(
            ctx.readBuffer, ctx.transport, ctx.aead, ctx.serverHsTraffic, ctx.serverHsSeq,
            ctx.crypto, ctx.onDebug,
        );
        ctx.readBuffer = result.readBuffer;
        ctx.serverHsSeq++;
        const messages = splitHandshakeMessages(result.whole);
        ctx.onDebug?.(`consumeServerFlight: split into ${messages.length} handshake message(s)`);
        const first = messages.shift();
        if (first === undefined) {
            throw new TlsHandshakeError("encrypted_extensions", {
                cause: new Error("decrypted record contained no handshake messages"),
            });
        }
        pendingMessages = messages;
        return { whole: first, body: first.subarray(4) };
    }

    // EncryptedExtensions.
    ctx.currentPhase = "encrypted_extensions";
    ctx.onDebug?.("consumeServerFlight: expecting EncryptedExtensions");
    let message = await nextHandshakeMessage();
    phase = advanceHandshake(phase, HandshakeType.ENCRYPTED_EXTENSIONS);
    ctx.transcript.push(message.whole);
    const alpn = parseAlpnFromEncryptedExtensions(message.body);
    if (alpn !== undefined) {
        ctx.alpnProtocol = alpn;
    }
    ctx.onDebug?.(`consumeServerFlight: EncryptedExtensions consumed (alpn=${alpn ?? "none"})`);

    // Certificate.
    ctx.currentPhase = "certificate";
    ctx.onDebug?.("consumeServerFlight: expecting Certificate");
    message = await nextHandshakeMessage();
    if (message.whole[0] === HandshakeType.COMPRESSED_CERTIFICATE) {
        // RFC 8879: a server sends CompressedCertificate (type 25) only when the
        // client advertised compress_certificate (ext 27). We never advertise it,
        // so this means a non-conformant server or a ClientHello that was modified
        // in transit (e.g. a CDN injecting the extension). Provide an actionable
        // error so the operator can diagnose the root cause.
        throw new TlsHandshakeError("certificate", {
            cause: new Error(
                "server sent a CompressedCertificate (RFC 8879, type 25) but this client did not advertise " +
                    "compress_certificate (ext 27). The server is non-conformant or a middlebox injected the " +
                    "extension. If ext 27 is in the profile extensionOrder, remove it.",
            ),
        });
    }
    if (message.whole[0] !== HandshakeType.CERTIFICATE) {
        throw new TlsHandshakeError("certificate", {
            cause: new Error(
                `expected Certificate (type ${HandshakeType.CERTIFICATE}), got handshake type ${message.whole[0]}`,
            ),
        });
    }
    phase = advanceHandshake(phase, HandshakeType.CERTIFICATE);
    ctx.transcript.push(message.whole);
    const chain = await validateCertificateChain(message.body, serverName, trustAnchors, now, ctx.crypto);
    ctx.peerCertificate = chain.leaf;
    ctx.onDebug?.(`consumeServerFlight: Certificate validated (${chain.intermediates.length} intermediates)`);

    // CertificateVerify.
    ctx.currentPhase = "certificate_verify";
    ctx.onDebug?.("consumeServerFlight: expecting CertificateVerify");
    message = await nextHandshakeMessage();
    phase = advanceHandshake(phase, HandshakeType.CERTIFICATE_VERIFY);

    // Verify the signature BEFORE pushing CertificateVerify to the transcript.
    // The signed content covers Transcript-Hash(ClientHello..Certificate) — the
    // transcript at this point still ends at Certificate, which is exactly the
    // content the server signed (RFC 8446 §4.4.3). Pushing afterward would
    // pollute the hash for the Finished verification, which covers
    // ClientHello..CertificateVerify.
    if (ctx.peerCertificate === undefined) {
        throw new TlsHandshakeError("certificate_verify", {
            cause: new Error("CertificateVerify received before a Certificate message was consumed"),
        });
    }
    ctx.onDebug?.("consumeServerFlight: verifying CertificateVerify signature against leaf cert SPKI");
    verifyCertificateVerify(
        message.body,
        ctx.peerCertificate.subjectPublicKeyInfo,
        ctx.transcript,
        ctx.hash,
        ctx.crypto,
    );
    ctx.transcript.push(message.whole);
    ctx.onDebug?.("consumeServerFlight: CertificateVerify signature verified OK");

    // Finished — verify against the transcript *before* appending the Finished.
    ctx.currentPhase = "finished";
    ctx.onDebug?.("consumeServerFlight: expecting Finished, computing transcript hash");
    const finishedTranscript = transcriptHash(ctx.transcript, ctx.hash, ctx.crypto);
    message = await nextHandshakeMessage();
    ctx.onDebug?.("consumeServerFlight: verifying server Finished verify_data");
    verifyServerFinished(message.body, finishedTranscript, ctx.hash, ctx.serverHsTrafficSecret, ctx.crypto);
    advanceHandshake(phase, HandshakeType.FINISHED);
    ctx.transcript.push(message.whole);
    ctx.onDebug?.("consumeServerFlight: server Finished verified OK");
}
