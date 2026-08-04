/**
 * In-memory StreamTransport stand-in for connection-layer tests.
 *
 * The record layer and handshake driver depend on a {@link StreamTransport}
 * byte stream: `write()` hands bytes off, `read()` returns the next chunk. This
 * fake buffers every write into a queue and replays queued chunks on read(), so
 * tests can drive framing / encryption round-trips and handshake simulations
 * without a real socket.
 */

import type { StreamTransport } from "@browsercore/transport";

export class FakeTransport implements StreamTransport {
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
