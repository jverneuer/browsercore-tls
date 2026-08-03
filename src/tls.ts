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

import { crypto, type HashId } from "@browsercore/crypto";
import type { Transport } from "@browsercore/transport";
import {
    TLS_1_3,
    type ApplicationData,
    type ApplicationTrafficSecrets,
    type CipherSuite,
    type ClientHelloConfig,
    type CloseReason,
    type KeyPair,
    type ProtocolVersion,
    type TlsConnection,
    type TlsOptions,
    type TlsSessionId,
    type TlsState,
    type TrafficSecrets,
} from "./types.js";
import { TlsHandshakeError, ensureTlsError, type TlsError } from "./errors.js";
import { createId } from "./utils.js";
import { ContentType, type encryptRecord } from "./record/record.js";
import type { Certificate } from "./certificates/certificates.js";
import type { ServerHello } from "./handshake/handshake.js";
import {
    ensureOpen,
    handleAlert as handleAlertRecord,
    emitError,
    notifyClose,
    withTimeout,
    readEncryptedRecord,
    writeEncryptedRecord,
    runHandshake,
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
    const conn = new TlsConnectionImpl(options);
    await conn.handshake();
    return conn;
}

/** Generate key shares for the requested groups (delegates to @browsercore/crypto). */
export function generateKeyShares(groups: readonly string[]): Promise<KeyPair[]> {
    // Wrapped in .then() so a synchronous throw (unsupported group) becomes a
    // rejected promise — callers await this and tests assert with .rejects.
    return Promise.resolve().then(() => {
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

    private applicationSecrets!: ApplicationTrafficSecrets;
    private clientAppSeq = 0;
    private serverAppSeq = 0;

    /** Decrypted application payloads awaiting consumption by read(). */
    private appReadQueue: Uint8Array[] = [];

    /** Lifecycle observers. */
    private closeListeners: ((reason: CloseReason) => void)[] = [];
    private errorListeners: ((error: TlsError) => void)[] = [];

    // `options` is optional so a connection can be constructed in isolation (e.g.
    // to assert on its default public fields) without a live transport. The real
    // entry point, connectTls, always supplies a full options object.
    constructor(options?: TlsOptions) {
        if (options !== undefined) {
            this.transport = options.transport;
            this.serverName = options.serverName;
            this.trustAnchors = options.trustAnchors ?? [];

            // An explicit alpnProtocols option overrides whatever the profile says.
            this.profile =
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
        await withTimeout(timeoutMs, () => this.performHandshake());
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
                throw new TlsHandshakeError("finished", {
                    cause: new Error("application data queue emptied between check and shift"),
                });
            }
            return { payload };
        }
        // Read encrypted records until an application-data payload arrives.
        for (;;) {
            const { innerType, content, readBuffer } = await readEncryptedRecord(
                this.readBuffer,
                this.transport,
                this.aead,
                this.applicationSecrets.server,
                this.serverAppSeq,
            );
            this.readBuffer = readBuffer;
            this.serverAppSeq++;
            if (innerType === ContentType.APPLICATION_DATA) {
                return { payload: content };
            }
            this.handlePostHandshakeRecord(innerType, content);
        }
    }

    public write(data: Uint8Array): Promise<void> {
        // Not async: there are no awaits. Synchronous throws (e.g. ensureOpen) are
        // caught and returned as a rejected promise so callers can await uniformly.
        try {
            ensureOpen(this.state);
            const traffic = this.applicationSecrets.client;
            // Split into record-sized plaintext fragments (TLS records cap at 2^14 bytes).
            for (let offset = 0; offset < data.length; offset += 16_384) {
                const fragment = data.subarray(offset, Math.min(offset + 16_384, data.length));
                writeEncryptedRecord(
                    this.transport,
                    this.aead,
                    traffic,
                    ContentType.APPLICATION_DATA,
                    fragment,
                    this.clientAppSeq,
                );
                this.clientAppSeq++;
            }
            return Promise.resolve();
        } catch (cause) {
            return Promise.reject(ensureTlsError(cause));
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
                writeEncryptedRecord(
                    this.transport,
                    this.aead,
                    this.applicationSecrets.client,
                    ContentType.ALERT,
                    alert,
                    this.clientAppSeq,
                );
            } catch {
                // ignore — we are closing anyway
            }
        }
        await this.transport.close();
        this.transition({ state: "closed", reason: { kind: "close_notify" } });
        notifyClose(this.closeListeners, { kind: "close_notify" });
    }

    public on(event: "close" | "error", listener: (arg: CloseReason | TlsError) => void): this {
        // A listener accepting the union is assignable to each slot by parameter
        // contravariance — no cast needed (the one that lived here was redundant).
        if (event === "close") {
            this.closeListeners.push(listener);
        } else {
            this.errorListeners.push(listener);
        }
        return this;
    }

    // -------------------------------------------------------------------------
    // Handshake + post-handshake record handling.
    // -------------------------------------------------------------------------

    /**
     * Run the handshake via the driver module. The driver mutates this object's
     * HandshakeContext fields and returns the derived application secrets, which
     * we store for read()/write(). `now` is read here (in the orchestrator) so
     * certificate validation stays pure and testable.
     */
    private async performHandshake(): Promise<void> {
        this.state = { state: "handshaking" };
        const now = Math.floor(Date.now() / 1000);
        this.applicationSecrets = await runHandshake(
            this,
            this.profile,
            this.serverName,
            this.trustAnchors,
            generateKeyShares,
            now,
        );
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

    /** Handle a non-application record encountered while reading application data. */
    private handlePostHandshakeRecord(innerType: ContentType, content: Uint8Array): void {
        switch (innerType) {
            case ContentType.ALERT:
                this.handleAlert(content);
                break;
            case ContentType.HANDSHAKE:
                // Post-handshake handshake (e.g. NewSessionTicket, KeyUpdate) — out of
                // scope for the happy path; ignore but do not error.
                break;
            case ContentType.CHANGE_CIPHER_SPEC:
            case ContentType.APPLICATION_DATA:
                // Neither should appear here: application data is the only expected
                // outer type, and TLS 1.3 has no change_cipher_spec. Reject typed.
                throw new TlsHandshakeError("finished", {
                    cause: new Error(`unexpected post-handshake record type ${innerType}`),
                });
        }
    }

    /**
     * Translate a received alert into a typed error or a graceful close. The
     * mapping is a pure function in the lifecycle module; this applies its
     * result to the connection's state.
     */
    private handleAlert(content: Uint8Array): void {
        const { close, error } = handleAlertRecord(content);
        if (close) {
            // close_notify — graceful.
            this.transition({ state: "closed", reason: { kind: "close_notify" } });
            return;
        }
        if (error !== undefined) {
            // TlsAlertError extends Error, not TlsError — wrap it so listeners
            // receive a uniform TlsError, matching the pre-refactor behavior.
            emitError(this.errorListeners, ensureTlsError(error));
        }
    }

    private transition(next: TlsState): void {
        this.state = next;
    }
}
