/**
 * Concurrent-write regression test over a real TLS peer.
 *
 * TLS 1.3 record sequence numbers are write-order-critical. The HTTP/2 layer
 * fires connection-preface frames (SETTINGS + WINDOW_UPDATE) as concurrent,
 * unawaited `tls.write()` calls — if two calls interleave, both encrypt with
 * the same sequence number and the peer rejects the duplicate with
 * `bad_record_mac`. Real CDNs (Cloudflare/BoringSSL) surfaced exactly this;
 * loopback tests with a single write path never caught it.
 *
 * The connection serializes all encrypted-record writes through one promise
 * chain; this test fires three writes CONCURRENTLY at a real node:tls peer
 * and requires the peer to decrypt and echo all of them.
 */

import { describe, expect, it } from "vitest";
import tls from "node:tls";
import { readFileSync } from "node:fs";
import { connect } from "@browsercore/transport";
import { connectTls } from "../src/tls.js";
import { TLS_1_3 } from "../src/types.js";
import type { Net, DnsResolver, ConnectOptions, Socket, IPAddress } from "@browsercore/contracts";
import { connect as netConnect } from "node:net";
import { lookup as dnsLookup } from "node:dns";
import { createMockEventProvider, createTestCryptoProvider } from "./test-helpers.js";

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

const nodeDns: DnsResolver = {
    lookup(hostname, family) {
        return new Promise((resolve, reject) => {
            dnsLookup(hostname, { family }, (err, address, resolvedFamily) => {
                if (err) {
                    reject(err);
                    return;
                }
                const result: IPAddress = { address, family: (resolvedFamily || family) as 4 | 6 };
                resolve([result]);
            });
        });
    },
};

const TLS_OPTIONS = {
    key: readFileSync(new URL("./fixtures/loopback/server-key.pem", import.meta.url)),
    cert: readFileSync(new URL("./fixtures/loopback/server-cert.pem", import.meta.url)),
};

describe("concurrent application writes", () => {
    it("delivers three concurrent writes with unique sequence numbers (bad_record_mac regression)", async () => {
        // Echo server: tags and returns every decrypted chunk it receives. If
        // any record arrives with a duplicate sequence number, the peer aborts
        // with bad_record_mac and the echo stream stops — the missing tag fails
        // the assertion.
        const server = tls.createServer(TLS_OPTIONS, (sock) => {
            sock.on("data", (chunk: Buffer) => {
                sock.write(Buffer.concat([Buffer.from("echo:"), chunk, Buffer.from(";")]));
            });
        });
        await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
        const port = (server.address() as { port: number }).port;

        try {
            const transport = await connect({
                host: "127.0.0.1",
                port,
                ipv6: false,
                net: nodeNet,
                dns: nodeDns,
                events: createMockEventProvider(),
            });
            const conn = await connectTls({
                transport,
                serverName: "localhost",
                profile: {
                    cipherSuites: ["TLS_AES_128_GCM_SHA256"],
                    extensionOrder: [0, 10, 13, 43, 51],
                    keyShareGroups: ["x25519"],
                    signatureAlgorithms: ["ecdsa_secp256r1_sha256"],
                    supportedVersions: [TLS_1_3],
                    grease: false,
                    serverName: "localhost",
                    alpnProtocols: ["http/1.1"],
                },
                events: createMockEventProvider(),
                crypto: createTestCryptoProvider(),
            });
            expect(conn.state.state).toBe("open");

            // The regression: three CONCURRENT writes (mirrors the h2 preface
            // pattern — SETTINGS and WINDOW_UPDATE are sent unawaited).
            const encoder = new TextEncoder();
            await Promise.all([
                conn.write(encoder.encode("AAAAAAAAAA")),
                conn.write(encoder.encode("BBBBBBBBBB")),
                conn.write(encoder.encode("CCCCCCCCCC")),
            ]);

            const decoder = new TextDecoder();
            let received = "";
            const deadline = Date.now() + 5000;
            while (!received.includes("echo:AAAAAAAAAA;") || !received.includes("echo:BBBBBBBBBB;") || !received.includes("echo:CCCCCCCCCC;")) {
                if (Date.now() > deadline) {
                    throw new Error(`peer echoed incompletely: "${received}"`);
                }
                const { payload } = await conn.read();
                received += decoder.decode(payload);
            }

            await conn.close();
        } finally {
            await new Promise<void>((resolve) => server.close(() => resolve()));
        }
    }, 15_000);
});
