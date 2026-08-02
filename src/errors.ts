/**
 * Typed errors for @network/tls.
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

/** The handshake phase at which a {@link TlsHandshakeError} occurred. */
export type HandshakePhase =
    | "client_hello"
    | "server_hello"
    | "certificate"
    | "finished";

/** The TLS handshake failed at a specific phase. */
export class TlsHandshakeError extends Error {
    public readonly kind = "TlsHandshakeError" as const;
    public readonly phase: HandshakePhase;
    public override readonly cause: Error | undefined;

    constructor(phase: HandshakePhase, options?: { cause?: Error }) {
        super(`TLS handshake failed during ${phase}`);
        this.name = "TlsHandshakeError";
        this.phase = phase;
        this.cause = options?.cause;
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
