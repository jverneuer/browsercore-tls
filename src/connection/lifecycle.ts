/**
 * Connection lifecycle: timeouts, alerts, state transitions, error emission.
 *
 * The bookkeeping around a connection's lifetime — racing the handshake against
 * a timeout, translating a received alert into a typed error, moving between
 * lifecycle states, and notifying observers. Kept as thin functions over
 * explicit state so the connection class stays a coordinator rather than owning
 * this plumbing.
 */

import { systemClock, type Clock, type TlsState } from "../types.js";
import { TlsAlertError, TlsHandshakeError, type HandshakePhase } from "../errors.js";
import { ContentType } from "../record/record.js";
import { assertNever } from "../utils.js";

/**
 * Race `run` against a timeout, rejecting with a handshake error if it fires.
 *
 * `getPhase` is queried at timeout-fire time so the error reports the phase the
 * handshake was actually in when it stalled — not a hardcoded guess. The caller
 * (the connection) exposes a mutable `currentPhase` field that the driver
 * updates before each step, and passes `() => this.currentPhase` here.
 */
export async function withTimeout(
    ms: number,
    run: () => Promise<void>,
    clock: Clock = systemClock,
    getPhase: () => HandshakePhase = () => "init",
): Promise<void> {
    const timeout = clock.sleep(ms).then(() => {
        throw new TlsHandshakeError(getPhase(), {
            cause: new Error(`handshake timed out after ${ms}ms`),
        });
    });
    await Promise.race([run(), timeout]);
}

/**
 * Handle a non-application record encountered while reading application data.
 *
 * Routes alerts to {@link handleAlert}, ignores post-handshake handshake
 * messages (NewSessionTicket — out of scope for the happy path), and rejects
 * any {@link ContentType.CHANGE_CIPHER_SPEC} or
 * {@link ContentType.APPLICATION_DATA} that appears *inside* an encrypted
 * record (application data is only valid as the outer record type; TLS 1.3 has
 * no change_cipher_spec). Returns `true` if the alert was a close_notify and
 * the connection should close gracefully.
 *
 * Note: the connection class (`TlsConnectionImpl.handlePostHandshakeRecord`)
 * now handles post-handshake records inline — including KeyUpdate key rotation
 * (RFC 8446 §4.6.3) — rather than delegating to this function. This standalone
 * utility remains for testing and for code that operates outside the
 * connection lifecycle.
 */
export function handlePostHandshakeRecord(innerType: ContentType, content: Uint8Array): boolean {
    switch (innerType) {
        case ContentType.ALERT:
            return handleAlert(content).close;
        case ContentType.HANDSHAKE:
            // Post-handshake handshake (e.g. NewSessionTicket, KeyUpdate) — out of
            // scope for the happy path; ignore but do not error.
            return false;
        case ContentType.CHANGE_CIPHER_SPEC:
        case ContentType.APPLICATION_DATA:
            // Neither should appear here: application data is the only expected
            // outer type, and TLS 1.3 has no change_cipher_spec. Reject typed.
            throw new TlsHandshakeError("application", {
                cause: new Error(`unexpected post-handshake record type ${innerType}`),
            });
        default:
            return assertNever(innerType);
    }
}

/** Translate a received alert into a typed error and close the connection. */
export function handleAlert(content: Uint8Array): { close: boolean; error?: TlsAlertError } {
    if (content.length < 2) {
        return { close: false, error: new TlsAlertError("fatal", 0, { cause: new Error("truncated alert record") }) };
    }
    // content.length >= 2 (checked above) guarantees both indices are in bounds,
    // but noUncheckedIndexedAccess cannot prove it — read through locals.
    const levelByte = content[0];
    const description = content[1];
    if (levelByte === undefined || description === undefined) {
        return { close: false, error: new TlsAlertError("fatal", 0, { cause: new Error("truncated alert record") }) };
    }
    const level = levelByte === 0x02 ? "fatal" : "warning";
    if (description === 0) {
        // close_notify — graceful.
        return { close: true };
    }
    return { close: false, error: new TlsAlertError(level, description) };
}

/** Throw unless the connection is open. */
export function ensureOpen(state: TlsState): void {
    if (state.state !== "open") {
        throw new TlsHandshakeError("application", {
            cause: new Error(`connection not open (state: ${state.state})`),
        });
    }
}
