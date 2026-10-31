/**
 * ECH GREASE + RFC 8879 certificate compression tests.
 *
 * Both features close the JA4 extension-set gap against real Chrome
 * (14 -> 16 counted extensions): real Chrome sends encrypted_client_hello
 * (65037, GREASE body when no config) and compress_certificate (27, brotli).
 */

import { describe, expect, it } from "vitest";
import { brotliCompressSync, brotliDecompressSync } from "node:zlib";
import { buildClientHello, generateKeyShares, TLS_1_3 } from "../src/index.js";
import { ExtensionType } from "../src/extensions/extensions.js";
import { expandCompressedCertificate, parseCertCompressionFromEncryptedExtensions } from "../src/connection/handshake-messages.js";
import { TlsHandshakeError } from "../src/errors.js";
import { createTestCryptoProvider } from "./test-helpers.js";
import type { CompressionProvider } from "@browsercore/contracts";
import type { ClientHelloConfig } from "../src/types.js";

const crypto = createTestCryptoProvider();

/** Parse emitted extension (type -> body) pairs from a built ClientHello. */
function parseExtensions(hello: Uint8Array): Map<number, Uint8Array> {
    let o = 0;
    if (hello[0] === 0x16) {
        o = 5; // strip record header when present
    }
    o += 4 + 2 + 32; // handshake header + legacy version + random
    const sidLen = hello[o]!;
    o += 1 + sidLen;
    const csLen = (hello[o]! << 8) | hello[o + 1]!;
    o += 2 + csLen;
    o += 1 + hello[o]!; // compression methods
    const extLen = (hello[o]! << 8) | hello[o + 1]!;
    o += 2;
    const end = o + extLen;
    const out = new Map<number, Uint8Array>();
    while (o + 4 <= end) {
        const type = (hello[o]! << 8) | hello[o + 1]!;
        const len = (hello[o + 2]! << 8) | hello[o + 3]!;
        out.set(type, hello.subarray(o + 4, o + 4 + len));
        o += 4 + len;
    }
    return out;
}

const config: ClientHelloConfig = {
    cipherSuites: ["TLS_AES_128_GCM_SHA256"],
    extensionOrder: [0, 10, 11, 13, 16, 27, 43, 45, 51, 65281, 65037],
    keyShareGroups: ["x25519"],
    signatureAlgorithms: ["ecdsa_secp256r1_sha256"],
    supportedVersions: [TLS_1_3],
    grease: false,
    serverName: "example.com",
    alpnProtocols: ["h2", "http/1.1"],
};

async function build(): Promise<Map<number, Uint8Array>> {
    const pairs = await generateKeyShares(["x25519"], crypto);
    const hello = buildClientHello(config, pairs, () => 0.0, crypto);
    return parseExtensions(hello.bytes ?? hello);
}

describe("ECH GREASE (ext 65037)", () => {
    it("emits a well-formed outer GREASE body with a fresh random payload", async () => {
        const exts = await build();
        const body = exts.get(ExtensionType.ENCRYPTED_CLIENT_HELLO);
        expect(body).toBeDefined();
        // Exact wire shape observed from real Chrome 131 (218B total):
        // 00 00 01 00 01 <rand> | 0020 <32B enc> | 00B0 <176B payload>
        expect(body!.length).toBe(218);
        expect([...body!.subarray(0, 5)]).toEqual([0x00, 0x00, 0x01, 0x00, 0x01]);
        expect(body![6]).toBe(0x00); // enc length: 32
        expect(body![7]).toBe(0x20);
        expect(body![40]).toBe(0x00); // payload length: 176
        expect(body![41]).toBe(176);
        // Randomness: two builds never share the enc or jitter bytes.
        const again = await build();
        expect(Buffer.from(again.get(65037)!.subarray(5, 40))).not.toEqual(
            Buffer.from(body!.subarray(5, 40)),
        );
    });
});

describe("compress_certificate (ext 27)", () => {
    it("advertises exactly brotli, byte-identical to the golden chrome-131 capture", async () => {
        const exts = await build();
        expect([...exts.get(ExtensionType.COMPRESS_CERTIFICATE)!]).toEqual([0x02, 0x00, 0x02]);
    });
});

describe("expandCompressedCertificate (RFC 8879, type 25)", () => {
    // Minimal provider: only brotliDecompress is exercised by the tls layer.
    const brotliProvider = {
        brotliDecompress: (data: Uint8Array): Uint8Array =>
            new Uint8Array(brotliDecompressSync(Buffer.from(data))),
    } as unknown as CompressionProvider;

    /** Build a type-25 body in the VERIFIED wire layout (no request context). */
    function t25(list: Uint8Array, declaredUncompressed?: number): Uint8Array {
        const compressed = new Uint8Array(brotliCompressSync(Buffer.from(list)));
        const u = declaredUncompressed ?? list.length;
        const body = new Uint8Array(8 + compressed.length);
        body[0] = 0x00; // algorithm: brotli
        body[1] = 0x02;
        body[2] = (u >> 16) & 0xff;
        body[3] = (u >> 8) & 0xff;
        body[4] = u & 0xff;
        body[5] = (compressed.length >> 16) & 0xff;
        body[6] = (compressed.length >> 8) & 0xff;
        body[7] = compressed.length & 0xff;
        body.set(compressed, 8);
        return body;
    }

    it("round-trips a synthetic CompressedCertificate (verified Cloudflare layout)", () => {
        // The compressed payload is the COMPLETE plain Certificate body:
        // request context (empty) + certificate_list — returned as-is.
        const plainBody = new Uint8Array([0x00, 0x00, 0x00, 0x03, 0xaa, 0xbb, 0xcc]);
        const expanded = expandCompressedCertificate(t25(plainBody), brotliProvider);
        expect([...expanded]).toEqual([...plainBody]);
    });

    it("rejects a non-brotli algorithm selection", () => {
        const list = new Uint8Array([0x01, 0x02, 0x03]);
        const body = t25(list);
        body[1] = 0x01; // zlib
        expect(() => expandCompressedCertificate(body, brotliProvider)).toThrow(/algorithm/);
    });

    it("rejects a body whose compressed length does not close exactly", () => {
        const body = t25(new Uint8Array([0x01, 0x02, 0x03]));
        const truncated = body.subarray(0, body.length - 2);
        expect(() => expandCompressedCertificate(truncated, brotliProvider)).toThrow(/mismatch/);
    });

    it("rejects a declared-uncompressed mismatch after decompression", () => {
        const body = t25(new Uint8Array([0x01, 0x02, 0x03]), 999);
        expect(() => expandCompressedCertificate(body, brotliProvider)).toThrow(/declared/);
    });
});

describe("parseCertCompressionFromEncryptedExtensions", () => {
    it("reads the selected algorithm from the ext 27 body", () => {
        // EncryptedExtensions body = extensions block: len(2) + [type(2) len(2) data]
        const data = new Uint8Array([0x00, 0x02]); // brotli
        const body = new Uint8Array(2 + 4 + data.length);
        body[0] = 0x00;
        body[1] = 4 + data.length;
        body[2] = 0x00;
        body[3] = 0x1b; // 27
        body[4] = 0x00;
        body[5] = data.length;
        body.set(data, 6);
        expect(parseCertCompressionFromEncryptedExtensions(body)).toBe(0x0002);
    });

    it("returns undefined when the server did not negotiate compression", () => {
        expect(parseCertCompressionFromEncryptedExtensions(new Uint8Array([0x00, 0x00]))).toBeUndefined();
    });
});

describe("expandCompressedCertificate error paths", () => {
    const brotliProvider = {
        brotliDecompress: (data: Uint8Array): Uint8Array =>
            new Uint8Array(brotliDecompressSync(Buffer.from(data))),
    } as unknown as CompressionProvider;

    it("rejects a body shorter than the 8-byte header", () => {
        expect(() => expandCompressedCertificate(new Uint8Array(4), brotliProvider)).toThrow(/truncated/);
    });

    it("wraps a non-Error brotli failure", () => {
        const throwing = {
            brotliDecompress: (): Uint8Array => {
                throw "raw failure";
            },
        } as unknown as CompressionProvider;
        const compressed = new Uint8Array(brotliCompressSync(Buffer.from([0x01])));
        const body = new Uint8Array(8 + compressed.length);
        body[0] = 0x00;
        body[1] = 0x02;
        body[2] = 0x00;
        body[3] = 0x00;
        body[4] = 0x01;
        body[5] = (compressed.length >> 16) & 0xff;
        body[6] = (compressed.length >> 8) & 0xff;
        body[7] = compressed.length & 0xff;
        body.set(compressed, 8);
        expect(() => expandCompressedCertificate(body, throwing)).toThrow(TlsHandshakeError);
    });
});
