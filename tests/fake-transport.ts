/**
 * In-memory Transport stand-in for connection-layer tests.
 *
 * The record layer and handshake driver depend on a {@link Transport} byte
 * stream: `write()` hands bytes off, `read()` returns the next chunk. This fake
 * buffers every write into a queue and replays queued chunks on read(), so tests
 * can drive framing / encryption round-trips and handshake simulations without a
 * real socket. It extends EventEmitter to structurally satisfy the Transport
 * interface (which extends EventEmitter), though the connection code only ever
 * calls read()/write()/close().
 */

import { EventEmitter } from "node:events";
import type { Transport } from "@browsercore/transport";

export class FakeTransport extends EventEmitter implements Transport {
    public readonly id = "tst_test" as Transport["id"];
    public state: Transport["state"] = { state: "open" };

    /** Bytes written by the higher layer, in write order (each write = one entry). */
    public readonly written: Uint8Array[] = [];
    /** Chunks read() will hand back, in FIFO order. */
    public readonly readQueue: Uint8Array[] = [];
    /** True once close() was called. */
    public closed = false;

    public async write(data: Uint8Array): Promise<void> {
        this.written.push(data);
    }

    public async read(): Promise<Uint8Array> {
        const chunk = this.readQueue.shift();
        if (chunk !== undefined) {
            return chunk;
        }
        // No data available: park forever so the record layer's ensureBytes loop
        // only completes when a chunk is queued. Tests that expect a read to
        // resolve always pre-seed readQueue before invoking the code under test.
        return new Promise<Uint8Array>(() => {});
    }

    public async close(): Promise<void> {
        this.closed = true;
        this.state = { state: "closed", reason: { kind: "client_close" } };
    }

    /** Concatenate everything written so far into a single buffer (test helper). */
    public allWritten(): Uint8Array {
        let total = 0;
        for (const c of this.written) {
            total += c.length;
        }
        const out = new Uint8Array(total);
        let o = 0;
        for (const c of this.written) {
            out.set(c, o);
            o += c.length;
        }
        return out;
    }
}
