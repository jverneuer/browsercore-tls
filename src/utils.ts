/**
 * Small shared helpers for @browsercore/tls.
 *
 * Kept dependency-free so every package can copy the pattern without pulling in
 * cross-package imports.
 */

import { systemClock, type Clock } from "./types.js";

/**
 * Exhaustiveness check for `switch`/`if-else` over discriminated unions.
 * Call in the `default` branch: `default: assertNever(x)`.
 * Adding a new union member forces every handler to compile-error until handled.
 */
// eslint-disable-next-line @typescript-eslint/no-unused-vars
export function assertNever(x: never): never {
    throw new Error(`Unexpected value: ${JSON.stringify(x)}`);
}

/** Monotonic-ish unique id generator (not cryptographically random). */
export function createId(prefix: string, clock: Clock = systemClock): string {
    return `${prefix}_${clock.now().toString(36)}_${Math.floor(Math.random() * 1e6).toString(36)}`;
}

/**
 * Constant-time byte comparison. Length-equal only — it leaks whether the
 * lengths match (an unavoidable side channel), but never the contents. Used
 * where a naive `===` on SPKI bytes would let an attacker learn how many
 * leading bytes match via timing.
 */
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) {
        return false;
    }
    let diff = 0;
    for (let i = 0; i < a.length; i++) {
        // Lengths are equal here (checked above), so both indices are in bounds —
        // but noUncheckedIndexedAccess cannot prove it, so read through locals.
        const ai = a[i];
        const bi = b[i];
        if (ai === undefined || bi === undefined) {
            return false;
        }
        diff |= ai ^ bi;
    }
    return diff === 0;
}
