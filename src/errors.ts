/**
 * Typed errors for @browsercore/tls.
 *
 * Errors are part of the API — every failure mode is an explicit type so callers
 * can match on `kind` instead of parsing messages.
 */

import { assertNever } from "./utils.js";

/** Base class for all TLS errors. Carries arbitrary structured details. */
export class TlsError extends Error {
    public readonly kind = "TlsError" as const;
    public readonly details: Record<string, unknown>;
    /** `Error | undefined` (not `?`) so assignment is valid under exactOptionalPropertyTypes. */
    public override readonly cause: Error | undefined;

    constructor(
        message: string,
        details: Record<string, unknown> = {},
        options?: { cause?: Error },
    ) {
        super(message, options);
        this.name = new.target.name;
        this.details = details;
        this.cause = options?.cause;
    }
}

/**
 * The handshake phase at which a {@link TlsHandshakeError} occurred.
 *
 * Granular enough that a timeout or error tells the caller (and the diagnostic
 * debug trace) EXACTLY which step was in progress. The driver updates a
 * `currentPhase` field before each step so {@link withTimeout} can report the
 * true stall location rather than a hardcoded phase.
 */
export type HandshakePhase =
    | "init"
    | "client_hello"
    | "server_hello"
    | "key_exchange"
    | "encrypted_extensions"
    | "certificate"
    | "certificate_verify"
    | "finished"
    | "client_finished"
    | "application";

/** The TLS handshake failed at a specific phase. */
export class TlsHandshakeError extends Error {
    public readonly kind = "TlsHandshakeError" as const;
    public readonly phase: HandshakePhase;
    public override readonly cause: Error | undefined;

    constructor(phase: HandshakePhase, options?: { cause?: Error }) {
        const cause = options?.cause;
        // Surface the underlying cause in the message so the specific reason is
        // visible without drilling into `.cause`; the cause is still attached for
        // programmatic inspection (matching the convention in the other test files).
        super(cause ? `TLS handshake failed during ${phase}: ${cause.message}` : `TLS handshake failed during ${phase}`);
        this.name = "TlsHandshakeError";
        this.phase = phase;
        this.cause = cause;
    }
}

/** Record decryption failed — authentication tag mismatch or corrupt input. */
export class TlsDecryptError extends Error {
    public readonly kind = "TlsDecryptError" as const;
    public readonly algorithm: string;
    /** `Error | undefined` (not `?`) so assignment is valid under exactOptionalPropertyTypes. */
    public override readonly cause: Error | undefined;

    constructor(algorithm: string, options?: { cause?: Error }) {
        super(`Decryption failed for ${algorithm}: authentication mismatch or corrupt input`);
        this.name = "TlsDecryptError";
        this.algorithm = algorithm;
        this.cause = options?.cause;
    }
}

/** Alert level of a TLS alert, per RFC 8446 §6. */
export type AlertLevel = "warning" | "fatal";

/**
 * TLS alert descriptions (IANA TLS Alert Registry, RFC 8446 §6).
 *
 * Only the values this client needs to *send* are defined here. Received alert
 * descriptions are passed through as raw numbers (see {@link TlsAlertError}).
 */
export const AlertDescription = {
    /** Graceful close (RFC 8446 §6.1). */
    CLOSE_NOTIFY: 0,
    /** Unacceptable cipher suite or version negotiation. */
    HANDSHAKE_FAILURE: 40,
    /** Certificate chain validation or hostname check failed. */
    BAD_CERTIFICATE: 42,
    /** A handshake parameter was illegal or inconsistent (e.g. downgrade sentinel). */
    ILLEGAL_PARAMETER: 47,
    /** A handshake cryptographic operation failed (signature or Finished mismatch). */
    DECRYPT_ERROR: 51,
    /** Unexpected exception not covered by a more specific alert. */
    INTERNAL_ERROR: 80,
} as const;

/** Union of alert-description values this client can send. */
export type AlertDescription = (typeof AlertDescription)[keyof typeof AlertDescription];

/** A TLS alert received from the peer (or sent to the peer). */
export class TlsAlertError extends Error {
    public readonly kind = "TlsAlertError" as const;
    public readonly level: AlertLevel;
    /** Numeric alert description, per IANA TLS Alert Registry. */
    public readonly description: number;
    public override readonly cause: Error | undefined;

    constructor(level: AlertLevel, description: number, options?: { cause?: Error }) {
        super(`TLS alert (${level}): description ${description}`);
        this.name = "TlsAlertError";
        this.level = level;
        this.description = description;
        this.cause = options?.cause;
    }
}

/**
 * A code path that has not been implemented yet.
 *
 * Used by placeholder extension builders (and any future stubs) so the failure
 * is a typed, identifiable error rather than a bare `Error`. The message keeps
 * the "not implemented" phrase so existing `/not implemented/` assertions still
 * match.
 */
export class NotImplementedError extends Error {
    public readonly kind = "NotImplementedError" as const;
    public readonly feature: string;
    public override readonly cause: Error | undefined;

    constructor(feature: string, options?: { cause?: Error }) {
        super(`not implemented — ${feature} (see PLAN.md)`);
        this.name = "NotImplementedError";
        this.feature = feature;
        this.cause = options?.cause;
    }
}

/** A PEM block was missing the required BEGIN/END CERTIFICATE markers. */
export class TlsPemError extends Error {
    public readonly kind = "TlsPemError" as const;
    public override readonly cause: Error | undefined;

    constructor(message: string, options?: { cause?: Error }) {
        super(message);
        this.name = "TlsPemError";
        this.cause = options?.cause;
    }
}

/** A TLS key-schedule computation rejected its inputs (e.g. HKDF-Expand overflow). */
export class TlsKeyScheduleError extends Error {
    public readonly kind = "TlsKeyScheduleError" as const;
    public readonly hash: string;
    public override readonly cause: Error | undefined;

    constructor(hash: string, message: string, options?: { cause?: Error }) {
        super(message);
        this.name = "TlsKeyScheduleError";
        this.hash = hash;
        this.cause = options?.cause;
    }
}

/** Narrow a caught error to a typed TLS error, or wrap it in {@link TlsError}. */
export function ensureTlsError(e: unknown): TlsError {
    if (e instanceof TlsError) {
        return e;
    }
    if (e instanceof Error) {
        return new TlsError(e.message, {}, { cause: e });
    }
    return new TlsError(typeof e === "string" ? e : "unknown TLS error");
}

void assertNever; // referenced for tree-shaking safety in bundlers
