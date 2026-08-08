/**
 * Shared test helpers for TLS tests — an in-memory EventProvider mock.
 *
 * The TLS connection requires an injected EventProvider (no fallback); every
 * test must inject one. This mock implements the full EventProvider interface
 * so tests can construct connections without pulling in node:events.
 */

import type { EventProvider } from "@browsercore/contracts";

/**
 * Create a minimal in-memory EventProvider. Stand-in for the Node
 * EventEmitter-backed provider that browsersmith injects in production.
 *
 * @returns A fresh EventProvider backed by an in-memory listener map.
 */
export function createMockEventProvider(): EventProvider {
    const listeners = new Map<string, Set<(...args: unknown[]) => void>>();
    return {
        on(event, listener) {
            if (!listeners.has(event)) listeners.set(event, new Set());
            listeners.get(event)!.add(listener);
        },
        once(event, listener) {
            const wrapped = (...args: unknown[]) => {
                listeners.get(event)?.delete(wrapped);
                listener(...args);
            };
            this.on(event, wrapped);
        },
        off(event, listener) {
            listeners.get(event)?.delete(listener);
        },
        removeListener(event, listener) {
            listeners.get(event)?.delete(listener);
        },
        emit(event, ...args) {
            const set = listeners.get(event);
            if (!set || set.size === 0) return false;
            for (const l of [...set]) l(...args);
            return true;
        },
        listenerCount(event) {
            return listeners.get(event)?.size ?? 0;
        },
        removeAllListeners(event) {
            if (event) listeners.delete(event);
            else listeners.clear();
        },
    };
}
