/**
 * PEM container decoding (RFC 7468).
 *
 * Server certificates arrive over the wire as DER, but tooling and trust-anchor
 * stores hand us PEM — base64 between BEGIN/END CERTIFICATE markers. This module
 * is the only place that knows about that text wrapper; everything downstream
 * (parsing, validation) consumes raw DER and never sees the container.
 */

import { TlsPemError } from "../errors.js";

/** Parse a PEM block (base64 between BEGIN/END CERTIFICATE) into DER bytes. */
export function pemToDer(pem: string): Uint8Array {
    const beginMarker = "-----BEGIN CERTIFICATE-----";
    const endMarker = "-----END CERTIFICATE-----";
    const begin = pem.indexOf(beginMarker);
    const end = pem.indexOf(endMarker);
    if (begin === -1 || end === -1 || end <= begin) {
        throw new TlsPemError("pemToDer: missing BEGIN/END CERTIFICATE markers");
    }
    const body = pem.slice(begin + beginMarker.length, end);
    // Strip all whitespace (newlines, spaces) and base64-decode.
    const cleaned = body.replaceAll(/\s+/gu, "");
    const binary = base64Decode(cleaned);
    return new Uint8Array(binary);
}

/** Base64-decode a string into bytes (no node:crypto dependency). */
function base64Decode(input: string): Uint8Array {
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const decodeTable = new Int16Array(128).fill(-1);
    for (let i = 0; i < alphabet.length; i++) {
        const code = alphabet.codePointAt(i);
        if (code !== undefined) {
            decodeTable[code] = i;
        }
    }
    // Strip padding to compute output length.
    let padding = 0;
    for (let i = input.length - 1; i >= 0; i--) {
        if (input[i] === "=") {
            padding++;
        } else {
            break;
        }
    }
    const cleanLen = input.length - padding;
    const outLen = Math.floor((cleanLen * 6) / 8);
    const out = new Uint8Array(outLen);
    let buffer = 0;
    let bitsCollected = 0;
    let outIndex = 0;
    for (let i = 0; i < cleanLen; i++) {
        const code = input.codePointAt(i);
        if (code === undefined) {
            continue;
        }
        const value = decodeTable[code];
        if (value === undefined || value < 0) {
            continue; // skip any non-alphabet char (shouldn't happen post-clean)
        }
        buffer = (buffer << 6) | value;
        bitsCollected += 6;
        if (bitsCollected >= 8) {
            bitsCollected -= 8;
            out[outIndex++] = (buffer >> bitsCollected) & 0xff;
        }
    }
    return out;
}
