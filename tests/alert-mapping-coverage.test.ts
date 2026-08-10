/**
 * Coverage tests for defensive error branches in tls.ts.
 *
 * Covers the private errorToAlertDescription() mapping (RFC 8446 §6) and the
 * handleKeyUpdate() empty-body guard (RFC 8446 §4.6.3). These branches are
 * exercised by constructing the appropriate typed error objects and invoking
 * the methods through a type-narrowed accessor — no source modification needed.
 *
 * Branches covered:
 * - errorToAlertDescription: cause message includes "downgrade" → ILLEGAL_PARAMETER
 * - errorToAlertDescription: cause message includes "illegal" → ILLEGAL_PARAMETER
 * - errorToAlertDescription: TlsHandshakeError phase "certificate" → BAD_CERTIFICATE
 * - errorToAlertDescription: cause is TlsDecryptError → DECRYPT_ERROR
 * - handleKeyUpdate: body.length === 0 → throws TlsHandshakeError
 */

import { describe, it, expect } from "vitest";
import { TlsConnectionImpl } from "../src/tls.js";
import {
    TlsError,
    TlsHandshakeError,
    TlsDecryptError,
    AlertDescription,
    type TlsError as TlsErrorType,
} from "../src/errors.js";
import { createTestCryptoProvider } from "./test-helpers.js";

const crypto = createTestCryptoProvider();

/**
 * Access the private errorToAlertDescription method on a TlsConnectionImpl.
 * The connection is constructed without options (no transport needed) — the
 * method is pure and does not touch connection state.
 */
function errorToAlertDescription(error: TlsErrorType): number {
    const conn = new TlsConnectionImpl(undefined, crypto);
    return (
        conn as unknown as { errorToAlertDescription(e: TlsErrorType): number }
    ).errorToAlertDescription.call(conn, error);
}

/**
 * Invoke the private handleKeyUpdate method on a TlsConnectionImpl. The
 * empty-body guard fires before any connection state is accessed, so a bare
 * (optionless) instance is sufficient.
 */
function handleKeyUpdate(body: Uint8Array): Promise<void> {
    const conn = new TlsConnectionImpl(undefined, crypto);
    return (
        conn as unknown as { handleKeyUpdate(b: Uint8Array): Promise<void> }
    ).handleKeyUpdate.call(conn, body);
}

describe("errorToAlertDescription — ILLEGAL_PARAMETER for downgrade/illegal messages", () => {
    it("maps a 'downgrade' cause message to ILLEGAL_PARAMETER (47)", () => {
        const error = new TlsError("downgrade sentinel", {}, {
            cause: new TlsHandshakeError("server_hello", {
                cause: new Error("downgrade sentinel detected in ServerHello random"),
            }),
        });
        expect(errorToAlertDescription(error)).toBe(AlertDescription.ILLEGAL_PARAMETER);
    });

    it("maps an 'illegal' cause message to ILLEGAL_PARAMETER (47)", () => {
        const error = new TlsError("illegal parameter", {}, {
            cause: new TlsHandshakeError("server_hello", {
                cause: new Error("illegal parameter in key_share extension"),
            }),
        });
        expect(errorToAlertDescription(error)).toBe(AlertDescription.ILLEGAL_PARAMETER);
    });
});

describe("errorToAlertDescription — BAD_CERTIFICATE for certificate phase", () => {
    it("maps a certificate-phase TlsHandshakeError to BAD_CERTIFICATE (42)", () => {
        const error = new TlsError("cert failed", {}, {
            cause: new TlsHandshakeError("certificate", {
                cause: new Error("hostname does not match the leaf certificate"),
            }),
        });
        expect(errorToAlertDescription(error)).toBe(AlertDescription.BAD_CERTIFICATE);
    });
});

describe("errorToAlertDescription — DECRYPT_ERROR for TlsDecryptError cause", () => {
    it("maps a TlsDecryptError cause to DECRYPT_ERROR (51)", () => {
        const error = new TlsError("decrypt failed", {}, {
            cause: new TlsDecryptError("AES-128-GCM"),
        });
        expect(errorToAlertDescription(error)).toBe(AlertDescription.DECRYPT_ERROR);
    });
});

describe("handleKeyUpdate — empty body guard", () => {
    it("throws TlsHandshakeError when the body is empty (length 0)", async () => {
        await expect(handleKeyUpdate(new Uint8Array(0))).rejects.toThrow(TlsHandshakeError);
    });

    it("includes a descriptive cause message for the empty body", async () => {
        try {
            await handleKeyUpdate(new Uint8Array(0));
            expect.unreachable("expected handleKeyUpdate to throw");
        } catch (e) {
            const err = e as TlsHandshakeError;
            expect(err.cause?.message).toMatch(/too short for request_update/);
        }
    });
});
