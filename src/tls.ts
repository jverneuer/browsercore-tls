/**
 * @browsercore/tls — public entry point.
 *
 * Establishes a TLS 1.3 connection over an existing byte-stream transport.
 * Wires together the record layer, handshake state machine, key schedule, and
 * certificate validation — consuming @browsercore/transport and @browsercore/crypto,
 * never node:crypto directly.
 *
 * TLS 1.2 fallback is intentionally NOT implemented: this client speaks TLS 1.3
 * only. Requesting a TLS 1.2 (only) handshake is rejected up front with a typed
 * error rather than failing silently mid-flight.
 */

import { crypto, SHA_384 } from "@browsercore/crypto";
import type { HashId } from "@browsercore/crypto";
import type { Transport } from "@browsercore/transport";
import type {
    ApplicationData,
    ApplicationTrafficSecrets,
    CipherSuite,
    ClientHelloConfig,
    CloseReason,
    KeyPair,
    NamedGroup,
    ProtocolVersion,
    TlsConnection,
    TlsOptions,
    TlsSessionId,
    TlsState,
    TrafficSecrets,
} from "./types.js";
import { TLS_1_3 } from "./types.js";
import type { TlsError } from "./errors.js";
import { TlsAlertError, TlsHandshakeError, ensureTlsError } from "./errors.js";
import { createId } from "./utils.js";
import {
    cipherSuiteToAead,
    ContentType,
    decryptRecord,
    encryptRecord,
    parseRecordHeader,
    serializeRecordHeader,
} from "./record/record.js";
import {
    advanceHandshake,
    buildClientHello,
    parseServerHello,
    recordServerHello,
    HandshakeType,
} from "./handshake/handshake.js";
import type { HandshakePhase, ServerHello } from "./handshake/handshake.js";
import {
    cipherSuiteToHash,
    deriveApplicationSecrets,
    deriveHandshakeTrafficSecrets,
    deriveTrafficSecrets,
    hkdfExpandLabel,
} from "./crypto/keySchedule.js";
import {
    ExtensionType,
    findExtension,
    parseExtensions,
    wireToNamedGroup,
} from "./extensions/extensions.js";
import { parseCertificate, validateHostname, verifyChain } from "./certificates/certificates.js";
import type { Certificate, CertificateChain, TrustAnchor } from "./certificates/certificates.js";

/** Default handshake timeout in milliseconds. */
const DEFAULT_HANDSHAKE_TIMEOUT_MS = 10_000;

/** AEAD authentication tag length for every cipher we support (bytes). */
const AEAD_TAG_LENGTH = 16;

/**
 * Key-share groups the crypto backend can actually generate. @browsercore/crypto
 * exposes only X25519 key generation today, so the handshake restricts itself to
 * that group. Any profile advertising only other groups cannot be satisfied.
 */
const SUPPORTED_KEY_SHARE_GROUPS: readonly NamedGroup[] = ["x25519"];

/** Map a negotiated cipher suite to the hash function used for its transcript. */
function hashFor(cipherSuite: CipherSuite): HashId {
    return cipherSuiteToHash(cipherSuite);
}

/** Output length (bytes) of the hash used by a cipher suite. */
function hashLengthFor(hash: HashId): number {
    return hash === SHA_384 ? 48 : 32;
}

/** Concatenate byte chunks into a single buffer. */
function concat(...chunks: readonly Uint8Array[]): Uint8Array {
    let total = 0;
    for (const c of chunks) {
        total += c.length;
    }
    const out = new Uint8Array(total);
    let o = 0;
    for (const c of chunks) {
        out.set(c, o);
        o += c.length;
    }
    return out;
}

/**
 * Build the per-record AEAD nonce by XOR-ing the (zero-padded, big-endian)
 * sequence number into the static IV — exactly TLS 1.3 §5.3.
 */
function xorNonce(iv: Uint8Array, seq: number): Uint8Array {
    const nonce = Uint8Array.from(iv);
    let s = seq;
    for (let i = nonce.length - 1; i >= nonce.length - 8 && s > 0; i--) {
        // bitwise XOR assign: flip the low byte of s into nonce[i]. The loop
        // bounds guarantee i is a valid index, so the non-null assertion is safe.
        nonce[i]! ^= s & 0xff;
        s = Math.floor(s / 256);
    }
    return nonce;
}

/** Constant-time byte comparison (length-equal only; leaks length, not contents). */
function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) {
        return false;
    }
    let diff = 0;
    for (let i = 0; i < a.length; i++) {
        diff |= a[i]! ^ b[i]!;
    }
    return diff === 0;
}

/**
 * Establish a TLS 1.3 connection over the given transport.
 *
 * Performs the full TLS 1.3 handshake, derives traffic secrets, and returns a
 * {@link TlsConnection} that transparently encrypts/decrypts application data.
 *
 * @example
 * ```ts
 * const transport = await connect({ host: "example.com", port: 443 });
 * const tls = await connectTls({
 *     transport,
 *     serverName: "example.com",
 *     profile: resolveProfile("modern-tls13", "example.com"),
 *     alpnProtocols: ["h2", "http/1.1"],
 * });
 * await tls.write(new TextEncoder().encode("GET / HTTP/1.1\r\n"));
 * const chunk = await tls.read();
 * await tls.close();
 * ```
 */
export async function connectTls(options: TlsOptions): Promise<TlsConnection> {
    const conn = new TlsConnectionImpl(options);
    await conn.handshake();
    return conn;
}

/** Generate key shares for the requested groups (delegates to @browsercore/crypto). */
export async function generateKeyShares(groups: readonly string[]): Promise<KeyPair[]> {
    const shares: KeyPair[] = [];
    for (const group of groups) {
        if (group !== "x25519") {
            // @browsercore/crypto only exposes X25519 key generation today. Other
            // (EC)DHE groups would need a backend we do not have — fail fast and
            // typed rather than producing a bogus key.
            throw new TlsHandshakeError("client_hello", {
                cause: new Error(`key share group "${group}" is not supported by the crypto backend`),
            });
        }
        const kp = crypto.x25519GenerateKeyPair();
        shares.push({ algorithm: "x25519", privateKey: kp.secretKey, publicKey: kp.publicKey });
    }
    return shares;
}

/** Concrete TLS 1.3 connection implementation. */
export class TlsConnectionImpl implements TlsConnection {
    public readonly id: TlsSessionId = createId("tls") as TlsSessionId;
    public state: TlsState = { state: "connecting" };
    // This client speaks TLS 1.3 only, so the public fields default to the only
    // protocol version it can negotiate. They are overwritten once a ServerHello
    // is parsed. Defaults let a no-arg `new TlsConnectionImpl()` be inspected
    // without a live transport (used by the public-API-surface test).
    public cipherSuite: CipherSuite = "TLS_AES_128_GCM_SHA256";
    public protocolVersion: ProtocolVersion = TLS_1_3;
    public alpnProtocol?: string;
    /** The peer's leaf certificate, once the handshake has validated it. */
    public peerCertificate?: Certificate;

    private readonly _transport!: Transport;
    private readonly _profile!: ClientHelloConfig;
    private readonly _serverName!: string;
    private readonly _trustAnchors: readonly Uint8Array[] = [];

    /** Buffered bytes not yet consumed by the record framer. */
    private _readBuffer: Uint8Array = new Uint8Array(0);
    /** Running handshake transcript: full handshake messages (with 4-byte headers). */
    private _transcript: Uint8Array[] = [];

    private _aead!: Parameters<typeof encryptRecord>[4];
    private _hash!: HashId;

    private _serverHello!: ServerHello;

    private _clientHsTraffic!: TrafficSecrets;
    private _serverHsTraffic!: TrafficSecrets;
    private _clientHsTrafficSecret!: Uint8Array;
    private _serverHsTrafficSecret!: Uint8Array;
    private _masterSecret!: Uint8Array;
    private _applicationSecrets!: ApplicationTrafficSecrets;

    private _clientHsSeq = 0;
    private _serverHsSeq = 0;
    private _clientAppSeq = 0;
    private _serverAppSeq = 0;

    /** Decrypted application payloads awaiting consumption by read(). */
    private _appReadQueue: Uint8Array[] = [];

    /** Lifecycle observers. */
    private _closeListeners: ((reason: CloseReason) => void)[] = [];
    private _errorListeners: ((error: TlsError) => void)[] = [];

    // `options` is optional so a connection can be constructed in isolation (e.g.
    // to assert on its default public fields) without a live transport. The real
    // entry point, connectTls, always supplies a full options object.
    constructor(options?: TlsOptions) {
        if (options !== undefined) {
            this._transport = options.transport;
            this._serverName = options.serverName;
            this._trustAnchors = options.trustAnchors ?? [];

            // An explicit alpnProtocols option overrides whatever the profile says.
            this._profile =
                options.alpnProtocols !== undefined && options.alpnProtocols.length > 0
                    ? { ...options.profile, alpnProtocols: options.alpnProtocols }
                    : options.profile;
        }
    }

    // -------------------------------------------------------------------------
    // Public async handshake API.
    // -------------------------------------------------------------------------

    /**
     * Drive the TLS 1.3 handshake to completion. Idempotent: calling it more than
     * once on an open connection is a no-op.
     */
    public async handshake(timeoutMs: number = DEFAULT_HANDSHAKE_TIMEOUT_MS): Promise<void> {
        if (this.state.state === "open") {
            return;
        }
        await this._withTimeout(timeoutMs, () => this._performHandshake());
    }

    public async read(): Promise<ApplicationData> {
        this._ensureOpen();
        if (this._appReadQueue.length > 0) {
            return { payload: this._appReadQueue.shift()! };
        }
        // Read encrypted records until an application-data payload arrives.
        for (;;) {
            const { innerType, content } = await this._readEncryptedRecord(
                this._applicationSecrets.server,
                this._serverAppSeq,
            );
            this._serverAppSeq++;
            if (innerType === ContentType.APPLICATION_DATA) {
                return { payload: content };
            }
            this._handlePostHandshakeRecord(innerType, content);
        }
    }

    public async write(data: Uint8Array): Promise<void> {
        this._ensureOpen();
        const traffic = this._applicationSecrets.client;
        // Split into record-sized plaintext fragments (TLS records cap at 2^14 bytes).
        for (let offset = 0; offset < data.length; offset += 16_384) {
            const fragment = data.subarray(offset, Math.min(offset + 16_384, data.length));
            this._writeEncryptedRecord(traffic, ContentType.APPLICATION_DATA, fragment, this._clientAppSeq);
            this._clientAppSeq++;
        }
    }

    public async close(): Promise<void> {
        if (this.state.state === "closed") {
            return;
        }
        // Send close_notify under the current (application) traffic keys, then
        // tear down the transport. Best-effort: a failing alert must not mask the
        // close itself.
        if (this.state.state === "open") {
            try {
                const alert = new Uint8Array([0x01, 0x00]); // warning / close_notify
                this._writeEncryptedRecord(
                    this._applicationSecrets.client,
                    ContentType.ALERT,
                    alert,
                    this._clientAppSeq,
                );
            } catch {
                // ignore — we are closing anyway
            }
        }
        await this._transport.close();
        this._transition({ state: "closed", reason: { kind: "close_notify" } });
        for (const listener of this._closeListeners) {
            listener({ kind: "close_notify" });
        }
    }

    public on(event: "close" | "error", listener: (arg: CloseReason | TlsError) => void): this {
        if (event === "close") {
            this._closeListeners.push(listener as (reason: CloseReason) => void);
        } else {
            this._errorListeners.push(listener as (error: TlsError) => void);
        }
        return this;
    }

    // -------------------------------------------------------------------------
    // Handshake state machine (RFC 8446).
    // -------------------------------------------------------------------------

    private async _performHandshake(): Promise<void> {
        this.state = { state: "handshaking" };

        // TLS 1.3 only: reject a profile that cannot negotiate TLS 1.3.
        if (!this._profile.supportedVersions.some((v) => v.name === "TLS 1.3")) {
            throw new TlsHandshakeError("client_hello", {
                cause: new Error("TLS 1.2-only handshakes are not supported by this client"),
            });
        }

        // 1. Generate key shares for the groups the crypto backend supports.
        const desired = this._profile.keyShareGroups.filter((g) =>
            (SUPPORTED_KEY_SHARE_GROUPS as readonly string[]).includes(g),
        );
        if (desired.length === 0) {
            throw new TlsHandshakeError("client_hello", {
                cause: new Error("no supported key share groups in the selected profile"),
            });
        }
        const keyPairs = await generateKeyShares(desired);

        // 2. Build and send the ClientHello as a plaintext handshake record.
        const clientHello = buildClientHello(this._profile, keyPairs);
        this._transcript.push(clientHello);
        await this._writeRecord(ContentType.HANDSHAKE, clientHello);

        // 3. Read the ServerHello (still plaintext) and validate the negotiation.
        const shHeader = await this._readHeaderBytes();
        const shRecord = await this._readRawRecord(shHeader);
        if (shRecord.type !== ContentType.HANDSHAKE) {
            throw new TlsHandshakeError("server_hello", {
                cause: new Error(`expected handshake record, got content type ${shRecord.type}`),
            });
        }
        this._transcript.push(shRecord.fragment);
        const serverHello = parseServerHello(shRecord.fragment.subarray(4), {
            cipherSuites: this._profile.cipherSuites,
            supportedVersions: this._profile.supportedVersions,
        });

        this._serverHello = serverHello;
        this.cipherSuite = serverHello.cipherSuite;
        this.protocolVersion = serverHello.selectedVersion;
        this._aead = cipherSuiteToAead(this.cipherSuite);
        this._hash = hashFor(this.cipherSuite);

        // 4. (EC)DHE key exchange: recover the server's key share and compute the shared secret.
        const sharedSecret = this._computeSharedSecret(serverHello, keyPairs);

        // 5. Derive handshake traffic secrets from the ClientHello..ServerHello transcript.
        const helloTranscript = this._transcriptHash();
        const { masterSecret, clientTrafficSecret, serverTrafficSecret } = deriveHandshakeTrafficSecrets(
            sharedSecret,
            helloTranscript,
            this.cipherSuite,
        );
        this._masterSecret = masterSecret;
        this._clientHsTrafficSecret = clientTrafficSecret;
        this._serverHsTrafficSecret = serverTrafficSecret;
        this._clientHsTraffic = deriveTrafficSecrets(clientTrafficSecret, this.cipherSuite, this._hash);
        this._serverHsTraffic = deriveTrafficSecrets(serverTrafficSecret, this.cipherSuite, this._hash);

        // 6. Consume the server's encrypted flight: EncryptedExtensions, Certificate,
        //    CertificateVerify, Finished.
        await this._consumeServerFlight();

        // 7. Derive application traffic secrets from the full handshake transcript.
        const handshakeTranscript = this._transcriptHash();
        this._applicationSecrets = deriveApplicationSecrets(
            this._masterSecret,
            handshakeTranscript,
            this.cipherSuite,
        );

        // 8. Send the client Finished under the client handshake traffic key.
        await this._sendClientFinished();

        // 9. Transition to the open state; negotiated parameters are already exposed
        //    on the public fields (cipherSuite, protocolVersion, alpnProtocol, ...).
        // Under exactOptionalPropertyTypes, `alpnProtocol?` must be omitted (not
        // `undefined`) when the server did not negotiate one.
        this._transition({
            state: "open",
            sessionId: this.id,
            protocolVersion: this.protocolVersion,
            cipherSuite: this.cipherSuite,
            ...(this.alpnProtocol !== undefined ? { alpnProtocol: this.alpnProtocol } : {}),
        });
    }

    /**
     * Read the server's encrypted second flight message-by-message, advancing the
     * handshake state machine and updating the transcript. Server Finished is
     * verified against the transcript as it stood *before* the Finished message.
     */
    private async _consumeServerFlight(): Promise<void> {
        // The server_hello_received phase, carrying the parsed ServerHello forward
        // so advanceHandshake can validate the rest of the flight against it.
        let phase: HandshakePhase = recordServerHello(
            { phase: "client_hello_sent" },
            this._serverHello,
        );

        // EncryptedExtensions.
        let message = await this._readEncryptedHandshakeMessage(
            this._serverHsTraffic,
            this._serverHsSeq,
        );
        this._serverHsSeq++;
        phase = advanceHandshake(phase, HandshakeType.ENCRYPTED_EXTENSIONS);
        this._transcript.push(message.whole);
        this._handleEncryptedExtensions(message.body);

        // Certificate.
        message = await this._readEncryptedHandshakeMessage(this._serverHsTraffic, this._serverHsSeq);
        this._serverHsSeq++;
        phase = advanceHandshake(phase, HandshakeType.CERTIFICATE);
        this._transcript.push(message.whole);
        await this._handleCertificate(message.body);

        // CertificateVerify.
        message = await this._readEncryptedHandshakeMessage(this._serverHsTraffic, this._serverHsSeq);
        this._serverHsSeq++;
        phase = advanceHandshake(phase, HandshakeType.CERTIFICATE_VERIFY);
        this._transcript.push(message.whole);

        // Finished — verify against the transcript *before* appending the Finished.
        const finishedTranscript = this._transcriptHash();
        message = await this._readEncryptedHandshakeMessage(this._serverHsTraffic, this._serverHsSeq);
        this._serverHsSeq++;
        this._verifyServerFinished(message.body, finishedTranscript);
        advanceHandshake(phase, HandshakeType.FINISHED);
        this._transcript.push(message.whole);
    }

    // -------------------------------------------------------------------------
    // Record layer.
    // -------------------------------------------------------------------------

    /** Write an unencrypted record (used for the initial ClientHello/ServerHello). */
    private async _writeRecord(type: ContentType, fragment: Uint8Array): Promise<void> {
        await this._transport.write(concat(serializeRecordHeader(type, fragment.length), fragment));
    }

    /**
     * Read the 5-byte record header and return it raw (needed as AEAD AAD) plus
     * the parsed length. The caller is responsible for consuming the fragment.
     */
    private async _readHeaderBytes(): Promise<{ raw: Uint8Array; length: number }> {
        await this._ensureBytes(5);
        const raw = this._readBuffer.subarray(0, 5);
        const parsed = parseRecordHeader(raw);
        return { raw, length: parsed.length };
    }

    /** Read a complete record given its already-consumed header. */
    private async _readRawRecord(header: { raw: Uint8Array; length: number }): Promise<{
        type: ContentType;
        fragment: Uint8Array;
    }> {
        await this._ensureBytes(5 + header.length);
        // type is byte 0 of the header; parseRecordHeader already validated it.
        const type = header.raw[0] as ContentType;
        const fragment = this._readBuffer.subarray(5, 5 + header.length);
        this._readBuffer = this._readBuffer.subarray(5 + header.length);
        return { type, fragment };
    }

    /**
     * Read and decrypt one record, returning its inner content type and content.
     * TLS 1.3 wraps encrypted handshake messages in records whose outer type is
     * application_data; the real type is the last non-zero byte of the plaintext.
     */
    private async _readEncryptedRecord(
        traffic: TrafficSecrets,
        seq: number,
    ): Promise<{ innerType: ContentType; content: Uint8Array }> {
        const header = await this._readHeaderBytes();
        const record = await this._readRawRecord(header);
        if (record.type !== ContentType.APPLICATION_DATA) {
            throw new TlsHandshakeError("finished", {
                cause: new Error(`expected encrypted APPLICATION_DATA record, got ${record.type}`),
            });
        }
        const nonce = xorNonce(traffic.iv, seq);
        const plaintext = decryptRecord(record.fragment, traffic.key, nonce, header.raw, this._aead);
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
        const innerType = plaintext[end - 1] as ContentType;
        return { innerType, content: plaintext.subarray(0, end - 1) };
    }

    /** Pull bytes from the transport until at least `n` are buffered. */
    private async _ensureBytes(n: number): Promise<void> {
        while (this._readBuffer.length < n) {
            const chunk = await this._transport.read();
            this._readBuffer = concat(this._readBuffer, chunk);
        }
    }

    // -------------------------------------------------------------------------
    // Key exchange + transcript.
    // -------------------------------------------------------------------------

    /** Compute the (EC)DHE shared secret from the server's selected key share. */
    private _computeSharedSecret(serverHello: ServerHello, keyPairs: readonly KeyPair[]): Uint8Array {
        const extensions = parseExtensions(serverHello.extensions);
        const keyShare = findExtension(extensions, ExtensionType.KEY_SHARE);
        if (keyShare === undefined) {
            throw new TlsHandshakeError("server_hello", {
                cause: new Error("ServerHello missing required key_share extension"),
            });
        }
        // Server KeyShareEntry: group(2) || len(2) || key_exchange.
        if (keyShare.data.length < 4) {
            throw new TlsHandshakeError("server_hello", {
                cause: new Error("key_share entry truncated"),
            });
        }
        const group = wireToNamedGroup((keyShare.data[0]! << 8) | keyShare.data[1]!);
        const keyLen = (keyShare.data[2]! << 8) | keyShare.data[3]!;
        if (keyLen + 4 !== keyShare.data.length) {
            throw new TlsHandshakeError("server_hello", {
                cause: new Error("key_share key_exchange length mismatch"),
            });
        }
        const serverPublicKey = keyShare.data.subarray(4, 4 + keyLen);
        const myPair = keyPairs.find((kp) => kp.algorithm === group);
        if (myPair === undefined) {
            throw new TlsHandshakeError("server_hello", {
                cause: new Error(`server selected key share group ${group} we did not offer`),
            });
        }
        switch (group) {
            case "x25519":
                return crypto.x25519SharedSecret(myPair.privateKey, serverPublicKey);
            default:
                throw new TlsHandshakeError("server_hello", {
                    cause: new Error(`key exchange for group ${group} is not supported by the crypto backend`),
                });
        }
    }

    /** Hash the current handshake transcript with the negotiated cipher's hash. */
    private _transcriptHash(): Uint8Array {
        const blob = concat(...this._transcript);
        return this._hash === SHA_384 ? crypto.sha384(blob) : crypto.sha256(blob);
    }

    // -------------------------------------------------------------------------
    // Handshake message handling.
    // -------------------------------------------------------------------------

    /** Read one encrypted handshake message, decrypting and stripping the inner type. */
    private async _readEncryptedHandshakeMessage(
        traffic: TrafficSecrets,
        seq: number,
    ): Promise<{ whole: Uint8Array; body: Uint8Array }> {
        const header = await this._readHeaderBytes();
        const record = await this._readRawRecord(header);
        if (record.type !== ContentType.APPLICATION_DATA) {
            throw new TlsHandshakeError("finished", {
                cause: new Error(`expected encrypted APPLICATION_DATA record, got ${record.type}`),
            });
        }
        const nonce = xorNonce(traffic.iv, seq);
        const plaintext = decryptRecord(record.fragment, traffic.key, nonce, header.raw, this._aead);
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
        const innerType = plaintext[end - 1] as ContentType;
        const content = plaintext.subarray(0, end - 1);
        if (innerType !== ContentType.HANDSHAKE) {
            throw new TlsHandshakeError("finished", {
                cause: new Error(`expected inner handshake type, got ${innerType}`),
            });
        }
        // `content` is the full handshake message (4-byte header + body).
        return { whole: content, body: content.subarray(4) };
    }

    /** Extract the negotiated ALPN protocol from EncryptedExtensions, if any. */
    private _handleEncryptedExtensions(body: Uint8Array): void {
        const extensions = parseExtensions(body);
        const alpn = findExtension(extensions, ExtensionType.APPLICATION_LAYER_PROTOCOL_NEGOTIATION);
        if (alpn === undefined) {
            return;
        }
        // Server ALPN body: length-prefixed list with a single entry.
        if (alpn.data.length < 3) {
            return;
        }
        const nameLen = alpn.data[2]!;
        if (3 + nameLen > alpn.data.length) {
            return;
        }
        this.alpnProtocol = new TextDecoder().decode(alpn.data.subarray(3, 3 + nameLen));
    }

    /** Parse the Certificate message, validate hostname, and verify the chain. */
    private async _handleCertificate(body: Uint8Array): Promise<void> {
        const chain = this._parseCertificateMessage(body);
        this.peerCertificate = chain.leaf;
        if (!validateHostname(chain.leaf, this._serverName)) {
            throw new TlsHandshakeError("certificate", {
                cause: new Error(`hostname "${this._serverName}" does not match the leaf certificate`),
            });
        }
        // Full chain verification requires trust anchors. Without them we still
        // performed hostname validation above; chain verification is best-effort.
        if (this._trustAnchors.length > 0) {
            // Trust anchors arrive as raw DER root certificates; verifyChain wants
            // parsed TrustAnchor records (SPKI + subject). A trust anchor is a
            // self-signed root, so its issuer DN is also its subject.
            const anchors = this._trustAnchors.map((der): TrustAnchor => {
                const root = parseCertificate(der);
                return { subjectPublicKeyInfo: root.subjectPublicKeyInfo, subject: root.issuer };
            });
            await verifyChain(chain, anchors, this._serverName, Math.floor(Date.now() / 1000));
        }
    }

    /**
     * Parse a Certificate handshake message (RFC 8446 §4.4.2) into a chain. The
     * body is: certificate_request_context (length-prefixed, len 1) then a
     * length-prefixed list of CertificateEntry { cert_data, extensions }.
     */
    private _parseCertificateMessage(body: Uint8Array): CertificateChain {
        let o = 0;
        const ctxLen = body[o++]!;
        o += ctxLen;
        const listLen = (body[o++]! << 16) | (body[o++]! << 8) | body[o++]!;
        const listEnd = o + listLen;
        if (listEnd > body.length) {
            throw new TlsHandshakeError("certificate", {
                cause: new Error("certificate_list length exceeds message body"),
            });
        }
        const certs: Certificate[] = [];
        while (o < listEnd) {
            const certLen = (body[o++]! << 16) | (body[o++]! << 8) | body[o++]!;
            const certDer = body.subarray(o, o + certLen);
            o += certLen;
            const extLen = (body[o++]! << 8) | body[o++]!;
            o += extLen;
            certs.push(parseCertificate(certDer));
        }
        if (certs.length === 0) {
            throw new TlsHandshakeError("certificate", {
                cause: new Error("server sent an empty certificate_list"),
            });
        }
        const leaf = certs[0]!;
        const root = certs[certs.length - 1]!;
        const intermediates = certs.slice(1, certs.length - 1);
        return { leaf, intermediates, root };
    }

    /**
     * Verify the server's Finished message: HMAC(finished_key, transcript), where
     * finished_key = HKDF-Expand-Label(server_traffic_secret, "finished", "", Hash.length)
     * and the transcript is ClientHello..CertificateVerify (everything before Finished).
     */
    private _verifyServerFinished(body: Uint8Array, transcript: Uint8Array): void {
        const hashLen = hashLengthFor(this._hash);
        if (body.length !== hashLen) {
            throw new TlsHandshakeError("finished", {
                cause: new Error(`server Finished length ${body.length} != expected ${hashLen}`),
            });
        }
        const finishedKey = hkdfExpandLabel(
            this._serverHsTrafficSecret,
            "finished",
            new Uint8Array(0),
            hashLen,
            this._hash,
        );
        const expected = crypto.hmac(this._hash, finishedKey, transcript);
        if (!constantTimeEqual(body, expected)) {
            throw new TlsHandshakeError("finished", {
                cause: new Error("server Finished verify_data mismatch"),
            });
        }
    }

    /** Build and send the client Finished under the client handshake traffic key. */
    private async _sendClientFinished(): Promise<void> {
        const hashLen = hashLengthFor(this._hash);
        const transcript = this._transcriptHash();
        const finishedKey = hkdfExpandLabel(
            this._clientHsTrafficSecret,
            "finished",
            new Uint8Array(0),
            hashLen,
            this._hash,
        );
        const verifyData = crypto.hmac(this._hash, finishedKey, transcript);
        const message = new Uint8Array(4 + verifyData.length);
        message[0] = HandshakeType.FINISHED;
        message[1] = (verifyData.length >> 16) & 0xff;
        message[2] = (verifyData.length >> 8) & 0xff;
        message[3] = verifyData.length & 0xff;
        message.set(verifyData, 4);
        this._writeEncryptedRecord(this._clientHsTraffic, ContentType.HANDSHAKE, message, this._clientHsSeq);
        this._clientHsSeq++;
    }

    // -------------------------------------------------------------------------
    // Encrypted record I/O (handshake + application traffic).
    // -------------------------------------------------------------------------

    /**
     * Encrypt a payload under `traffic` and write it as an encrypted record whose
     * outer type is application_data. The inner content type byte is appended to
     * the plaintext before encryption.
     */
    private _writeEncryptedRecord(
        traffic: TrafficSecrets,
        innerType: ContentType,
        content: Uint8Array,
        seq: number,
    ): void {
        const plaintext = concat(content, new Uint8Array([innerType]));
        const header = serializeRecordHeader(
            ContentType.APPLICATION_DATA,
            plaintext.length + AEAD_TAG_LENGTH,
        );
        const nonce = xorNonce(traffic.iv, seq);
        const ciphertext = encryptRecord(plaintext, traffic.key, nonce, header, this._aead);
        void this._transport.write(concat(header, ciphertext));
    }

    /** Handle a non-application record encountered while reading application data. */
    private _handlePostHandshakeRecord(innerType: ContentType, content: Uint8Array): void {
        switch (innerType) {
            case ContentType.ALERT:
                this._handleAlert(content);
                break;
            case ContentType.HANDSHAKE:
                // Post-handshake handshake (e.g. NewSessionTicket, KeyUpdate) — out of
                // scope for the happy path; ignore but do not error.
                break;
            default:
                throw new TlsHandshakeError("finished", {
                    cause: new Error(`unexpected post-handshake record type ${innerType}`),
                });
        }
    }

    /** Translate a received alert into a typed error and close the connection. */
    private _handleAlert(content: Uint8Array): void {
        if (content.length < 2) {
            this._emitError(
                ensureTlsError(new TlsAlertError("fatal", 0, { cause: new Error("truncated alert record") })),
            );
            return;
        }
        const level = content[0]! === 0x02 ? "fatal" : "warning";
        const description = content[1]!;
        if (description === 0) {
            // close_notify — graceful.
            this._transition({ state: "closed", reason: { kind: "close_notify" } });
            return;
        }
        this._emitError(ensureTlsError(new TlsAlertError(level, description)));
    }

    // -------------------------------------------------------------------------
    // Timeouts + lifecycle.
    // -------------------------------------------------------------------------

    private async _withTimeout(ms: number, run: () => Promise<void>): Promise<void> {
        let timer: NodeJS.Timeout | undefined;
        const timeout = new Promise<never>((_, reject) => {
            timer = setTimeout(() => {
                reject(
                    new TlsHandshakeError("finished", {
                        cause: new Error(`handshake timed out after ${ms}ms`),
                    }),
                );
            }, ms);
        });
        try {
            await Promise.race([run(), timeout]);
        } finally {
            if (timer !== undefined) {
                clearTimeout(timer);
            }
        }
    }

    private _ensureOpen(): void {
        if (this.state.state !== "open") {
            throw new TlsHandshakeError("finished", {
                cause: new Error(`connection not open (state: ${this.state.state})`),
            });
        }
    }

    private _transition(next: TlsState): void {
        this.state = next;
    }

    private _emitError(error: TlsError): void {
        for (const listener of this._errorListeners) {
            listener(error);
        }
    }
}
