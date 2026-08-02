/**
 * @browsercore/tls — public entry point.
 *
 * Establishes a TLS 1.3 (with 1.2 fallback) connection over an existing
 * byte-stream transport. Wires together the record layer, handshake state
 * machine, key schedule, and certificate validation — consuming @browsercore/transport
 * and @browsercore/crypto, never node:crypto directly.
 */

import type { Transport } from "@browsercore/transport";
import type {
    ApplicationTrafficSecrets,
    CloseReason,
    KeyPair,
    TlsConnection,
    TlsOptions,
    TlsSessionId,
    TlsState,
} from "./types.js";
import type { TlsError } from "./errors.js";
import { TlsHandshakeError } from "./errors.js";
import { createId } from "./utils.js";
import { parseRecordHeader, serializeRecordHeader, RECORD_HEADER_SIZE } from "./record/record.js";
import { buildClientHello, parseServerHello } from "./handshake/handshake.js";

/** Default handshake timeout in milliseconds. */
const DEFAULT_HANDSHAKE_TIMEOUT_MS = 10_000;

/**
 * Establish a TLS connection over the given transport.
 *
 * Performs the full TLS 1.3 handshake (falling back to 1.2 if the server does
 * not support 1.3), derives traffic secrets, and returns a {@link TlsConnection}
 * that transparently encrypts/decrypts application data.
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
    // PLAN: implement the full handshake:
    //   1. Generate key shares for each group in options.profile.keyShareGroups
    //      via @browsercore/crypto -> KeyPair[].
    //   2. buildClientHello(options.profile, keyPairs) -> write handshake record.
    //   3. Read ServerHello record -> parseServerHello.
    //   4. (EC)DHE key exchange via @browsercore/crypto -> sharedSecret.
    //   5. deriveHandshakeSecrets / deriveApplicationSecrets.
    //   6. Read + decrypt EncryptedExtensions, Certificate, CertificateVerify, Finished.
    //   7. verifyChain against trust anchors + serverName.
    //   8. Send client Finished. Transition state to "open".
    //   Drive TlsState through connecting -> handshaking -> open.
    const handshakeTimeoutMs = options.handshakeTimeoutMs ?? DEFAULT_HANDSHAKE_TIMEOUT_MS;
    void handshakeTimeoutMs;
    void options;
    void parseRecordHeader;
    void serializeRecordHeader;
    void RECORD_HEADER_SIZE;
    void buildClientHello;
    void parseServerHello;
    throw new Error("not implemented — see PLAN.md");
}

/** Concrete TLS connection implementation (filled in per PLAN.md). */
export class TlsConnectionImpl implements TlsConnection {
    public readonly id: TlsSessionId = createId("tls") as TlsSessionId;
    public state: TlsState = { state: "connecting" };
    public readonly protocolVersion;
    public readonly cipherSuite;
    public readonly alpnProtocol?: string;

    // PLAN: hold the Transport, record read/write buffers, traffic secrets,
    //       handshake transcript hash, and handshake timeout handle here.
    private declare readonly _transport: Transport;
    private declare readonly _applicationSecrets: ApplicationTrafficSecrets;

    constructor() {
        // Placeholder values so the readonly fields are initialized.
        this.protocolVersion = { name: "TLS 1.3", wire: 0x0304 } as const;
        this.cipherSuite = "TLS_AES_128_GCM_SHA256" as const;
    }

    public async read(): Promise<{ payload: Uint8Array }> {
        this._ensureOpen();
        void this._applicationSecrets;
        throw new Error("not implemented — see PLAN.md");
    }

    public async write(_data: Uint8Array): Promise<void> {
        this._ensureOpen();
        void this._transport;
        throw new Error("not implemented — see PLAN.md");
    }

    public async close(): Promise<void> {
        throw new Error("not implemented — see PLAN.md");
    }

    public on(_event: "close" | "error", _listener: (arg: CloseReason | TlsError) => void): this {
        void _event;
        void _listener;
        throw new Error("not implemented — see PLAN.md");
    }

    private _ensureOpen(): void {
        if (this.state.state !== "open") {
            throw new TlsHandshakeError("finished", {
                cause: new Error(`connection not open (state: ${this.state.state})`),
            });
        }
    }
}

/** Generate key shares for the requested groups (delegates to @browsercore/crypto). */
export async function generateKeyShares(groups: readonly string[]): Promise<KeyPair[]> {
    // PLAN: for each group call @browsercore/crypto generateKeyPair(group).
    void groups;
    throw new Error("not implemented — see PLAN.md");
}
