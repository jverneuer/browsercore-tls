/**
 * Live-server TLS → HTTP round-trip regression test.
 *
 * Proves the full stack works end-to-end: TLS 1.3 handshake over a real TCP
 * transport → application data write (HTTP/1.1 request) → application data
 * read (HTTP response decryption). This is the ultimate integration guard —
 * if any layer regresses (key exchange, AEAD, record framing), the HTTP
 * round-trip fails.
 *
 * Gated behind RUN_LIVE_TESTS=1 so CI (which may have no network) stays
 * green — without the env var the suite is skipped entirely.
 *
 * Targets:
 *   - tls.peet.ws:443  — returns a JSON fingerprint echo at /api/all
 *   - example.com:443  — returns the classic IANA example HTML page
 */

import { describe, it, expect } from "vitest";
import { connect } from "@browsercore/transport";
import type { Net, DnsResolver, ConnectOptions, Socket, IPAddress } from "@browsercore/contracts";
import { connect as netConnect } from "node:net";
import { lookup as dnsLookup } from "node:dns";
import { createMockEventProvider, createTestCryptoProvider } from "./test-helpers.js";
import { connectTls } from "../src/tls.js";
import { TLS_1_3 } from "../src/types.js";
import type { ClientHelloConfig, TlsConnection } from "../src/types.js";

const RUN_LIVE_TESTS = process.env.RUN_LIVE_TESTS === "1";

const crypto = createTestCryptoProvider();
const decoder = new TextDecoder();
const encoder = new TextEncoder();

/** Real Node.js Net adapter backed by node:net for live TCP connections. */
const nodeNet: Net = {
    connect(options: ConnectOptions): Socket {
        return netConnect({
            host: options.host,
            port: options.port,
            noDelay: options.noDelay,
            localAddress: options.localAddress,
            family: options.family,
        }) as unknown as Socket;
    },
};

/** Real Node.js DnsResolver backed by node:dns.lookup. */
const nodeDns: DnsResolver = {
    lookup(hostname, family) {
        return new Promise((resolve, reject) => {
            dnsLookup(hostname, { family }, (err, address, resolvedFamily) => {
                if (err) {
                    reject(err);
                    return;
                }
                const result: IPAddress = {
                    address,
                    family: (resolvedFamily ?? family) as 4 | 6,
                };
                resolve([result]);
            });
        });
    },
};

/**
 * Minimal TLS 1.3 ClientHello profile for example.com.
 *
 * No ALPN is advertised — the server defaults to HTTP/1.1, which is what the
 * test sends. Identical to the profile in live-handshake.test.ts that has been
 * verified against example.com.
 */
const EXAMPLE_PROFILE: ClientHelloConfig = {
    cipherSuites: ["TLS_AES_128_GCM_SHA256"],
    extensionOrder: [0, 10, 13, 43, 51],
    keyShareGroups: ["x25519"],
    signatureAlgorithms: ["ecdsa_secp256r1_sha256"],
    supportedVersions: [TLS_1_3],
    serverName: "example.com",
    grease: false,
};

/**
 * TLS 1.3 ClientHello profile for tls.peet.ws.
 *
 * Peet.ws is stricter than example.com — it requires ALPN (extension 16) and
 * ec_point_formats (extension 11), and its certificate chain needs RSA-PSS
 * signature support. Without these the server sends a fatal handshake_failure
 * alert (code 40).
 */
const PEET_PROFILE: ClientHelloConfig = {
    cipherSuites: ["TLS_AES_128_GCM_SHA256"],
    extensionOrder: [0, 10, 11, 13, 16, 43, 51],
    keyShareGroups: ["x25519"],
    signatureAlgorithms: ["ecdsa_secp256r1_sha256", "rsa_pss_rsae_sha256"],
    supportedVersions: [TLS_1_3],
    serverName: "tls.peet.ws",
    grease: false,
    alpnProtocols: ["http/1.1"],
};

/**
 * Read all decrypted application data until the server closes the connection.
 *
 * With `Connection: close`, the server sends the full response followed by a
 * TLS close_notify alert. This loop accumulates every APPLICATION_DATA record
 * and stops when read() throws (state transitions to "closed").
 */
async function readAll(conn: TlsConnection): Promise<string> {
    const chunks: Uint8Array[] = [];
    for (;;) {
        try {
            const data = await conn.read();
            chunks.push(data.payload);
        } catch {
            break;
        }
        // Safety valve: stop after 1 MiB to avoid an unbounded loop.
        const total = chunks.reduce((sum, c) => sum + c.length, 0);
        if (total > 1_048_576) break;
    }

    const total = chunks.reduce((sum, c) => sum + c.length, 0);
    const merged = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
        merged.set(chunk, offset);
        offset += chunk.length;
    }
    return decoder.decode(merged);
}

/**
 * Build a minimal HTTP/1.1 GET request. `Connection: close` tells the server
 * to close the connection after sending the full response, simplifying the
 * read loop — no Content-Length or chunked-encoding parsing is needed.
 */
function httpRequest(host: string, path: string): Uint8Array {
    return encoder.encode(
        `GET ${path} HTTP/1.1\r\nHost: ${host}\r\nConnection: close\r\n\r\n`,
    );
}

(RUN_LIVE_TESTS ? describe : describe.skip)("live TLS → HTTP round-trip", () => {
    it("completes handshake and HTTP round-trip against tls.peet.ws", async () => {
        const transport = await connect({
            host: "tls.peet.ws",
            port: 443,
            connectTimeoutMs: 15_000,
            net: nodeNet,
            dns: nodeDns,
            events: createMockEventProvider(),
        });

        try {
            const conn = await connectTls({
                transport,
                crypto,
                serverName: "tls.peet.ws",
                profile: PEET_PROFILE,
                handshakeTimeoutMs: 25_000,
                events: createMockEventProvider(),
                onDebug: (msg: string) => console.error(`[tls-debug] ${msg}`),
            });

            expect(conn.state.state).toBe("open");

            await conn.write(httpRequest("tls.peet.ws", "/api/all"));
            const response = await readAll(conn);

            // The response is a full HTTP/1.1 message: status line + headers + body.
            expect(response).toContain("HTTP/1.1");
            expect(response.length).toBeGreaterThan(0);

            await conn.close();
        } finally {
            await transport.close();
        }
    }, 30_000);

    it("completes handshake and HTTP round-trip against example.com", async () => {
        const transport = await connect({
            host: "example.com",
            port: 443,
            connectTimeoutMs: 15_000,
            net: nodeNet,
            dns: nodeDns,
            events: createMockEventProvider(),
        });

        try {
            const conn = await connectTls({
                transport,
                crypto,
                serverName: "example.com",
                profile: EXAMPLE_PROFILE,
                handshakeTimeoutMs: 25_000,
                events: createMockEventProvider(),
                onDebug: (msg: string) => console.error(`[tls-debug] ${msg}`),
            });

            expect(conn.state.state).toBe("open");

            await conn.write(httpRequest("example.com", "/"));
            const response = await readAll(conn);

            expect(response).toContain("HTTP/1.1");
            expect(response.length).toBeGreaterThan(0);

            await conn.close();
        } finally {
            await transport.close();
        }
    }, 30_000);
});
