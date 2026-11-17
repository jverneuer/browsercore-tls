/**
 * In-memory StreamTransport stand-in for connection-layer tests.
 *
 * The record layer and handshake driver depend on a {@link StreamTransport}
 * byte stream: `write()` hands bytes off, `read()` returns the next chunk. This
 * fake buffers every write into a queue and replays queued chunks on read(), so
 * tests can drive framing / encryption round-trips and handshake simulations
 * without a real socket.
 *
 * It implements the FULL canonical `Transport` surface (contracts' `Transport`,
 * re-exported by @browsercore/transport as `StreamTransport`): `id`, `state`
 * and the seven `EventProvider` methods, not just write/read/close. Canonical
 * Transport grew the event surface + lifecycle state in transport 0.2.9's
 * replaceability-audit alignment; before the test-typecheck gate existed the
 * fakes silently lagged it (92 latent TS2740s — every inline fake derived from
 * this class). Subclasses overriding `close()` should call `super.close()` so
 * the recorded state transition and `"close"` emission still happen.
 */

import type { CloseReason, StreamTransport, TransportState } from "@browsercore/transport";

/** Listener shape required by the canonical EventProvider surface. */
type EventListener = (...args: unknown[]) => void;

export class FakeTransport implements StreamTransport {
    /** Opaque identifier for logging / correlation (canonical Transport.id). */
    public readonly id: string;
    /** Lifecycle state mirrored from write/close calls (canonical Transport.state). */
    public state: TransportState = { state: "open" };

    /** Bytes written by the higher layer, in write order (each write = one entry). */
    public readonly written: Uint8Array[] = [];
    /** Chunks read() will hand back, in FIFO order. */
    public readonly readQueue: Uint8Array[] = [];
    /** True once close() was called. */
    public closed = false;
    /** Registered event listeners, keyed by event name (EventProvider surface). */
    private readonly listeners = new Map<string, Set<EventListener>>();

    public constructor(id = "fake-transport") {
        this.id = id;
    }

    public on(event: string, listener: EventListener): void {
        this.register(event, listener);
    }

    public once(event: string, listener: EventListener): void {
        const firing: EventListener = (...args: unknown[]) => {
            this.listeners.get(event)?.delete(firing);
            listener(...args);
        };
        this.register(event, firing);
    }

    public off(event: string, listener: EventListener): void {
        this.listeners.get(event)?.delete(listener);
    }

    public removeListener(event: string, listener: EventListener): void {
        this.off(event, listener);
    }

    public emit(event: string, ...args: unknown[]): boolean {
        const eventListeners = this.listeners.get(event);
        if (eventListeners === undefined || eventListeners.size === 0) {
            return false;
        }
        for (const listener of [...eventListeners]) {
            listener(...args);
        }
        return true;
    }

    public listenerCount(event: string): number {
        return this.listeners.get(event)?.size ?? 0;
    }

    public removeAllListeners(event?: string): void {
        if (event === undefined) {
            this.listeners.clear();
        } else {
            this.listeners.delete(event);
        }
    }

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

    public async close(reason: CloseReason = { kind: "client_close" }): Promise<void> {
        this.closed = true;
        this.state = { state: "closed", reason };
        this.emit("close", reason);
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

    /** Shared registration path for on()/once() (once wraps before landing here). */
    private register(event: string, listener: EventListener): void {
        const existing = this.listeners.get(event);
        if (existing !== undefined) {
            existing.add(listener);
        } else {
            this.listeners.set(event, new Set([listener]));
        }
    }
}
