/**
 * @browsercore/tls — public entry point.
 *
 * Establishes a TLS 1.3 connection over an existing byte-stream transport.
 * Wires together the record layer, handshake state machine, key schedule, and
 * certificate validation — consuming @browsercore/transport and @browsercore/crypto,
 * never node:crypto directly.
 *
 * Supports TLS 1.3 (RFC 8446) with optional TLS 1.2 fallback (RFC 5246).
 * TLS 1.2 support is gated behind server negotiation: if the server selects a
 * TLS 1.2 cipher suite, the handshake driver branches to runTls12Handshake().
 *
 * The connection class is intentionally a thin coordinator: it owns the mutable
 * connection state (read buffer, sequence counters, traffic secrets, transcript)
 * and the public API, while every pure computation — record framing, key exchange,
 * transcript hashing, alert translation, and the handshake choreography itself —
 * lives in a focused module under `./connection/`. Those modules thread state
 * through explicit parameters and the {@link HandshakeContext} this class
 * implements, which keeps the byte-level logic unit-testable in isolation and
 * this file focused on the public surface.
 */

import type { EventProvider } from "@browsercore/contracts";
import type { CryptoProvider, HashId } from "@browsercore/crypto";
import type { Transport } from "@browsercore/transport";
import {
    systemClock,
    TLS_1_3,
    type ApplicationData,
    type ApplicationTrafficSecrets,
    type CipherSuite,
    type ClientHelloConfig,
    type CloseReason,
    type Clock,
    type KeyPair,
    type ProtocolVersion,
    type TlsConnection,
    type TlsOptions,
    type TlsSessionId,
    type TlsState,
    type TrafficSecrets,
} from "./types.js";
import { TlsHandshakeError, TlsDecryptError, AlertDescription, ensureTlsError, type AlertLevel, type HandshakePhase, type TlsError } from "./errors.js";
import { createId } from "./utils.js";
import { ContentType, type encryptRecord } from "./record/record.js";
import { HandshakeType, type ServerHello } from "./handshake/handshake.js";
import type { Certificate } from "./certificates/certificates.js";
import {
    ensureOpen,
    handleAlert as handleAlertRecord,
    withTimeout,
    readEncryptedRecord,
    writeEncryptedRecord,
    runHandshake,
    splitHandshakeMessages,
    updateTrafficSecrets,
    type HandshakeContext,
} from "./connection/index.js";

/** Default handshake timeout in milliseconds. */
const DEFAULT_HANDSHAKE_TIMEOUT_MS = 10_000;

/**
 * Establish a TLS 1.3 connection over the given transport.
 *
 * Performs the full TLS 1.3 handshake, derives traffic secrets, and returns a
 * {@link TlsConnection} that transparently encrypts/decrypts application data.
 * Callers pass an already-connected {@link Transport}, the server name (for SNI
 * + certificate validation), and a resolved profile (cipher suites, key-share
 * groups, signature algorithms).
 */
export async function connectTls(options: TlsOptions): Promise<TlsConnection> {
    const provider = options.crypto;
    const conn = new TlsConnectionImpl(options, provider);
    await conn.handshake();
    return conn;
}

/** Generate key shares for the requested groups (delegates to @browsercore/crypto). */
export function generateKeyShares(groups: readonly string[], provider: CryptoProvider): Promise<KeyPair[]> {
    // Wrapped in .then() so a synchronous throw (unsupported group) becomes a
    // rejected promise — callers await this and tests assert with .rejects.
    return Promise.resolve().then(() => {
        const shares: KeyPair[] = [];
        for (const group of groups) {
            switch (group) {
                // Post-quantum hybrid groups (RFC 8446 §4.2.7 + hybrid design).
                // Advertised in supported_groups but we send the classical
                // X25519 key_share — matching real Chrome hybrid mode. The
                // server combines it with its own PQ share if it supports the
                // hybrid group, so no separate PQ key pair is generated here.
                // These empty cases fall through to the x25519 case below.
                case "X25519Kyber768":
                case "X25519MLKEM768":
                case "Secp256r1MLKEM768":
                case "Secp384r1MLKEM1024":
                case "x25519": {
                    const kp = provider.x25519GenerateKeyPair();
                    shares.push({ algorithm: "x25519", privateKey: kp.secretKey, publicKey: kp.publicKey });
                    break;
                }
                case "secp256r1":
                case "secp384r1": {
                    const kp = provider.ecdhGenerateKeyPair(group);
                    shares.push({ algorithm: group, privateKey: kp.secretKey, publicKey: kp.publicKey });
                    break;
                }
                default:
                    // @browsercore/crypto only exposes X25519 and the two NIST ECDH
                    // curves today. Any other (EC)DHE group would need a backend we
                    // do not have — fail fast and typed rather than producing a
                    // bogus key.
                    throw new TlsHandshakeError("client_hello", {
                        cause: new Error(`key share group "${group}" is not supported by the crypto backend`),
                    });
            }
        }
        return shares;
    });
}

/**
 * Concrete TLS 1.3 connection implementation.
 *
 * Implements {@link HandshakeContext} so the handshake driver in
 * `./connection/handshake-driver.ts` can read and mutate its fields directly
 * (read buffer, transcript, traffic secrets, sequence counters) without the
 * choreography of the handshake living inline in this class.
 */
export class TlsConnectionImpl implements TlsConnection, HandshakeContext {
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

    // `transport` is public-read because the handshake driver (HandshakeContext)
    // needs it; it is NOT on the TlsConnection interface, so it does not leak into
    // the package's public API surface.
    public readonly transport!: Transport;
    private readonly profile!: ClientHelloConfig;
    private readonly serverName!: string;
    private readonly trustAnchors: readonly Uint8Array[] = [];
    /** Time source (defaults to systemClock). Injected via TlsOptions.clock. */
    private readonly clock: Clock;
    /** Cryptographic provider, injected via the constructor (never defaulted). */
    public readonly crypto!: CryptoProvider;

    // --- HandshakeContext: mutable handshake state (read/written by the driver) ---
    public readBuffer: Uint8Array = new Uint8Array(0);
    public readonly transcript: Uint8Array[] = [];
    public aead!: Parameters<typeof encryptRecord>[4];
    public hash!: HashId;
    public serverHello!: ServerHello;
    public clientHsTraffic!: TrafficSecrets;
    public serverHsTraffic!: TrafficSecrets;
    public clientHsTrafficSecret!: Uint8Array;
    public serverHsTrafficSecret!: Uint8Array;
    public masterSecret!: Uint8Array;
    public clientHsSeq = 0;
    public serverHsSeq = 0;
    /**
     * Raw application traffic secrets, retained for KeyUpdate key rotation
     * (RFC 8446 §4.6.3). Set by the driver when application secrets are derived.
     */
    public clientAppSecret!: Uint8Array;
    public serverAppSecret!: Uint8Array;
    /** True once handshake traffic keys are derived — gates sendAlert during handshake. */
    public hsTrafficReady = false;
    /** Mutable: current handshake phase, updated by the driver for timeout attribution. */
    public currentPhase: HandshakePhase = "init";
    /** Optional debug trace callback, set from TlsOptions.onDebug. */
    public onDebug: ((msg: string) => void) | undefined;

    private applicationSecrets!: ApplicationTrafficSecrets;
    private clientAppSeq = 0;
    private serverAppSeq = 0;

    /** Decrypted application payloads awaiting consumption by read(). */
    private appReadQueue: Uint8Array[] = [];

    /**
     * Injected event provider backend (decouples from node:events).
     *
     * Lifecycle events ("close", "error") are delegated to this provider, which
     * is supplied by the composition root (browsersmith). No fallback is created
     * here — the field is definitely assigned from `options.events` when options
     * is provided; a no-arg construction leaves it unset (tests only).
     */
    private readonly events!: EventProvider;

    // `options` is optional so a connection can be constructed in isolation (e.g.
    // to assert on its default public fields) without a live transport. The real
    // entry point, connectTls, always supplies a full options object. `provider`
    // is required — pure dependency injection, no fallback singleton.
    constructor(options: TlsOptions | undefined, provider: CryptoProvider) {
        // The clock defaults to the wall clock so production code never needs to
        // supply one. Assigned here (before the options guard) so both the no-arg
        // and full-options paths share the same default.
        this.clock = options?.clock ?? systemClock;
        this.crypto = provider;
        if (options !== undefined) {
            // `events` is required — a missing provider is a composition-root bug,
            // so fail fast with a typed error rather than silently dropping events.
            if (options.events === undefined) {
                throw new TlsHandshakeError("client_hello", {
                    cause: new Error("TlsConnectionImpl requires an injected EventProvider (options.events)"),
                });
            }
            this.events = options.events;
            this.transport = options.transport;
            this.serverName = options.serverName;
            this.trustAnchors = options.trustAnchors ?? [];
            this.onDebug = options.onDebug;

            // An explicit alpnProtocols option overrides whatever the profile says.
            this.profile =
                options.alpnProtocols !== undefined && options.alpnProtocols.length > 0
                    ? { ...options.profile, alpnProtocols: options.alpnProtocols }
                    : options.profile;
        }
    }

    // -------------------------------------------------------------------------
    // EventProvider delegation — decouples the connection from node:events.
    //
    // The injected EventProvider backend is the single source of truth for
    // lifecycle events. These methods forward to it so the connection stays
    // backend-agnostic (Node EventEmitter, EventTarget, mock).
    // -------------------------------------------------------------------------

    public on(event: "close" | "error", listener: (arg: CloseReason | TlsError) => void): this {
        // The injected provider type-erases listener args to `unknown`; cast at
        // the boundary (safe — callers pass "close"/"error" args per the
        // typed signature, and the provider forwards them verbatim).
        this.events.on(event, listener as (...args: unknown[]) => void);
        return this;
    }

    public once(event: string, listener: (...args: unknown[]) => void): void {
        this.events.once(event, listener);
    }

    public off(event: string, listener: (...args: unknown[]) => void): void {
        this.events.off(event, listener);
    }

    public removeListener(event: string, listener: (...args: unknown[]) => void): void {
        this.events.removeListener(event, listener);
    }

    public emit(event: string, ...args: unknown[]): boolean {
        return this.events.emit(event, ...args);
    }

    public listenerCount(event: string): number {
        return this.events.listenerCount(event);
    }

    public removeAllListeners(event?: string): void {
        this.events.removeAllListeners(event);
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
        await withTimeout(timeoutMs, () => this.performHandshake(), this.clock, () => this.currentPhase);
    }

    /**
     * Read the next chunk of decrypted application data. Blocks until a record
     * arrives; non-application records (alerts, post-handshake messages) are
     * handled inline.
     */
    public async read(): Promise<ApplicationData> {
        ensureOpen(this.state);
        if (this.appReadQueue.length > 0) {
            const payload = this.appReadQueue.shift();
            if (payload === undefined) {
                // Length was just checked; this is unreachable but required so the
                // non-null assertion can be dropped under noUncheckedIndexedAccess.
                throw new TlsHandshakeError("application", {
                    cause: new Error("application data queue emptied between check and shift"),
                });
            }
            return { payload };
        }
        // Read encrypted records until an application-data payload arrives.
        for (;;) {
            // Sequential by necessity: each iteration mutates readBuffer and
            // serverAppSeq and may early-return on APPLICATION_DATA; records must
            // be processed in order, so the read cannot be parallelized.
            // eslint-disable-next-line no-await-in-loop
            const { innerType, content, readBuffer } = await readEncryptedRecord(
                this.readBuffer,
                this.transport,
                this.aead,
                this.applicationSecrets.server,
                this.serverAppSeq,
                this.crypto,
                this.onDebug,
            );
            this.readBuffer = readBuffer;
            this.serverAppSeq++;
            if (innerType === ContentType.APPLICATION_DATA) {
                return { payload: content };
            }
            // eslint-disable-next-line no-await-in-loop
            await this.handlePostHandshakeRecord(innerType, content);
        }
    }

    public async write(data: Uint8Array): Promise<void> {
        try {
            ensureOpen(this.state);
            const traffic = this.applicationSecrets.client;
            // Split into record-sized plaintext fragments (TLS records cap at 2^14 bytes).
            for (let offset = 0; offset < data.length; offset += 16_384) {
                const fragment = data.subarray(offset, Math.min(offset + 16_384, data.length));
                // Sequential by necessity: each record carries a monotonically
                // increasing sequence number, so the writes cannot be parallelized.
                // eslint-disable-next-line no-await-in-loop
                await writeEncryptedRecord(
                    this.transport,
                    this.aead,
                    traffic,
                    ContentType.APPLICATION_DATA,
                    fragment,
                    this.clientAppSeq,
                    this.crypto,
                    this.onDebug,
                );
                this.clientAppSeq++;
            }
        } catch (cause) {
            throw ensureTlsError(cause);
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
                await writeEncryptedRecord(
                    this.transport,
                    this.aead,
                    this.applicationSecrets.client,
                    ContentType.ALERT,
                    alert,
                    this.clientAppSeq,
                    this.crypto,
                    this.onDebug,
                );
            } catch {
                // ignore — we are closing anyway
            }
        }
        await this.transport.close();
        this.transition({ state: "closed", reason: { kind: "close_notify" } });
        // Surface the close to observers via the injected provider (decouples
        // from node:events — no listener-array bookkeeping lives here anymore).
        this.events.emit("close", { kind: "close_notify" });
    }

    // -------------------------------------------------------------------------
    // Handshake + post-handshake record handling.
    // -------------------------------------------------------------------------

    /**
     * Run the handshake via the driver module. The driver mutates this object's
     * HandshakeContext fields and returns the derived application secrets, which
     * we store for read()/write(). `now` is read here (in the orchestrator) so
     * certificate validation stays pure and testable.
     *
     * Error cleanup (RFC 8446 §6): on any failure the method sends a fatal
     * alert (best-effort), closes the transport to prevent socket leaks, and
     * transitions to the `closed` terminal state before re-throwing.
     */
    private async performHandshake(): Promise<void> {
        this.state = { state: "handshaking" };
        const now = Math.floor(this.clock.now() / 1000);
        try {
            this.applicationSecrets = await runHandshake(
                this,
                this.profile,
                this.serverName,
                this.trustAnchors,
                (groups) => generateKeyShares(groups, this.crypto),
                now,
            );
        } catch (cause) {
            // Best-effort: send a fatal alert mapped to the error type, then
            // close the transport. Never let cleanup failures mask the original.
            const error = ensureTlsError(cause);
            await this.sendAlert("fatal", this.errorToAlertDescription(error));
            try {
                await this.transport.close();
            } catch {
                // Best-effort — the transport may already be broken.
            }
            this.transition({ state: "closed", reason: { kind: "error", error } });
            throw cause;
        }
        // Expose the negotiated parameters the driver wrote onto the context.
        this.protocolVersion = this.serverHello.selectedVersion;

        // Transition to the open state. Under exactOptionalPropertyTypes,
        // `alpnProtocol?` must be omitted (not `undefined`) when unset.
        this.transition({
            state: "open",
            sessionId: this.id,
            protocolVersion: this.protocolVersion,
            cipherSuite: this.cipherSuite,
            ...(this.alpnProtocol === undefined ? {} : { alpnProtocol: this.alpnProtocol }),
        });
    }

    /**
     * Send a TLS alert (RFC 8446 §6) to the peer.
     *
     * Best-effort: if the traffic keys are not yet derived (early handshake
     * failure), or the transport write fails, the alert is silently dropped.
     * The caller's error-handling path (transport close) is the fallback.
     *
     * During the handshake, the alert is sent under the client handshake traffic
     * key; after the handshake, under the client application traffic key.
     */
    public async sendAlert(level: AlertLevel, description: number): Promise<void> {
        try {
            const alertBody = new Uint8Array([level === "fatal" ? 0x02 : 0x01, description]);
            if (this.state.state === "handshaking" && this.hsTrafficReady) {
                await writeEncryptedRecord(
                    this.transport,
                    this.aead,
                    this.clientHsTraffic,
                    ContentType.ALERT,
                    alertBody,
                    this.clientHsSeq,
                    this.crypto,
                    this.onDebug,
                );
                this.clientHsSeq++;
            } else if (this.state.state === "open") {
                await writeEncryptedRecord(
                    this.transport,
                    this.aead,
                    this.applicationSecrets.client,
                    ContentType.ALERT,
                    alertBody,
                    this.clientAppSeq,
                    this.crypto,
                    this.onDebug,
                );
                this.clientAppSeq++;
            }
            // If neither condition holds (e.g. connecting state, before keys
            // derived), we cannot encrypt — skip silently. Best-effort by design.
        } catch {
            // Never let an alert-sending failure mask the original error.
        }
    }

    /**
     * Map a typed TLS error to the appropriate alert description for sending
     * before connection teardown (RFC 8446 §6).
     *
     * - `handshake_failure` (40): bad cipher suite / version negotiation
     * - `bad_certificate` (42): certificate chain or hostname validation failure
     * - `decrypt_error` (51): signature verification or Finished verify_data mismatch
     * - `illegal_parameter` (47): downgrade sentinel, unexpected message
     * - `internal_error` (80): anything not covered above
     */
    private errorToAlertDescription(error: TlsError): number {
        // ensureTlsError wraps non-TlsError exceptions (TlsHandshakeError,
        // TlsDecryptError) in a TlsError with the original as .cause.
        const cause = error.cause;
        if (cause instanceof TlsHandshakeError) {
            const message = cause.cause?.message ?? "";
            if (message.includes("downgrade") || message.includes("illegal")) {
                return AlertDescription.ILLEGAL_PARAMETER;
            }
            if (cause.phase === "certificate") {
                return AlertDescription.BAD_CERTIFICATE;
            }
            if (cause.phase === "certificate_verify" || cause.phase === "finished") {
                return AlertDescription.DECRYPT_ERROR;
            }
            return AlertDescription.HANDSHAKE_FAILURE;
        }
        if (cause instanceof TlsDecryptError) {
            return AlertDescription.DECRYPT_ERROR;
        }
        return AlertDescription.INTERNAL_ERROR;
    }

    /** Handle a non-application record encountered while reading application data. */
    private async handlePostHandshakeRecord(innerType: ContentType, content: Uint8Array): Promise<void> {
        if (innerType === ContentType.ALERT) {
            // Alerts need connection-specific handling (state transition + error
            // emission) that the shared dispatcher does not own.
            const { close, error } = handleAlertRecord(content);
            if (close) {
                this.transition({ state: "closed", reason: { kind: "close_notify" } });
                return;
            }
            if (error !== undefined) {
                // Surface the error to observers via the injected provider
                // (decouples from node:events — delegated, not re-emitted here).
                this.events.emit("error", ensureTlsError(error));
            }
            return;
        }
        if (innerType === ContentType.HANDSHAKE) {
            // Post-handshake handshake messages: KeyUpdate (RFC 8446 §4.6.3)
            // rotates traffic keys; NewSessionTicket and others are ignored for now.
            await this.handlePostHandshakeMessage(content);
            return;
        }
        // CHANGE_CIPHER_SPEC or APPLICATION_DATA inside an encrypted record:
        // neither is valid post-handshake. Reject typed.
        throw new TlsHandshakeError("application", {
            cause: new Error(`unexpected post-handshake record type ${innerType}`),
        });
    }

    /**
     * Split a decrypted post-handshake handshake record into individual messages
     * and dispatch each by type. KeyUpdate rotates traffic keys; all other types
     * (NewSessionTicket, post-handshake CertificateRequest) are silently ignored.
     */
    private async handlePostHandshakeMessage(content: Uint8Array): Promise<void> {
        const messages = splitHandshakeMessages(content);
        for (const msg of messages) {
            const typeByte = msg[0];
            if (typeByte === HandshakeType.KEY_UPDATE) {
                // eslint-disable-next-line no-await-in-loop
                await this.handleKeyUpdate(msg.subarray(4));
            }
            // Other post-handshake message types are ignored — they do not
            // affect the connection's traffic keys or state.
        }
    }

    /**
     * Handle a received KeyUpdate (RFC 8446 §4.6.3).
     *
     * Upon receiving KeyUpdate, the receiver MUST immediately update its
     * *receiving* keys (the keys for reading records from the sender) and reset
     * the corresponding sequence counter to zero. If `request_update` is
     * `update_requested` (1), the receiver MUST send its own KeyUpdate (with
     * `update_not_requested`) and then update its *sending* keys.
     */
    private async handleKeyUpdate(body: Uint8Array): Promise<void> {
        if (body.length === 0) {
            throw new TlsHandshakeError("application", {
                cause: new Error("KeyUpdate message body too short for request_update byte"),
            });
        }
        const requestUpdate = body[0];
        if (requestUpdate === undefined || requestUpdate > 1) {
            throw new TlsHandshakeError("application", {
                cause: new Error(`invalid KeyUpdate request_update value: ${requestUpdate}`),
            });
        }

        // Update receiving (server) keys immediately (RFC 8446 §4.6.3).
        const serverUpdate = updateTrafficSecrets(this.serverAppSecret, this.cipherSuite, this.crypto);
        this.applicationSecrets = { ...this.applicationSecrets, server: serverUpdate.traffic };
        this.serverAppSecret = serverUpdate.secret;
        this.serverAppSeq = 0;
        this.onDebug?.(`KeyUpdate: server (read) keys rotated, serverAppSeq reset to 0`);

        // If the server requested an update, send our KeyUpdate and then rotate
        // our sending (client) keys. The KeyUpdate is sent under the OLD client
        // keys; the new keys apply to all subsequent writes.
        if (requestUpdate === 1) {
            // Build KeyUpdate message: type(KEY_UPDATE=24) || length(3) || request_update(0).
            const keyUpdateMsg = new Uint8Array([HandshakeType.KEY_UPDATE, 0, 0, 1, 0]);
            await writeEncryptedRecord(
                this.transport,
                this.aead,
                this.applicationSecrets.client,
                ContentType.HANDSHAKE,
                keyUpdateMsg,
                this.clientAppSeq,
                this.crypto,
                this.onDebug,
            );
            this.clientAppSeq++;

            // Now rotate the client sending keys.
            const clientUpdate = updateTrafficSecrets(this.clientAppSecret, this.cipherSuite, this.crypto);
            this.applicationSecrets = { ...this.applicationSecrets, client: clientUpdate.traffic };
            this.clientAppSecret = clientUpdate.secret;
            this.clientAppSeq = 0;
            this.onDebug?.(`KeyUpdate: client (write) keys rotated, clientAppSeq reset to 0`);
        }
    }

    private transition(next: TlsState): void {
        this.state = next;
    }
}
