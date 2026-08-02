# TypeScript Coding Standards

These rules are the standard for this codebase and **every** sub-package. Every PR,
every AI-generated snippet, and every hand-written file follows them. They exist so
the intended behavior lives in the types — never in tribal knowledge or hidden assumptions.

> Design for AI modification: before committing, ask *"Could another developer or an
> LLM understand the intended behavior without asking me?"* If not — add types, split
> functions, clarify states, rename.

---

## 1. Strict compiler — never relax it

Every `tsconfig.json` inherits `tsconfig.base.json`, which carries:

```json
{
  "strict": true,
  "noUncheckedIndexedAccess": true,
  "exactOptionalPropertyTypes": true
}
```

- `noUncheckedIndexedAccess` → `arr[i]` is `T | undefined`.
- `exactOptionalPropertyTypes` → `?` means absent-or-present, not present-and-undefined.

Ambiguity creates bugs and forces LLMs to guess. **Never** override these to `false`
in a sub-package to dodge an error. Fix the error instead.

## 2. Every important data structure has a type

If data crosses a module boundary, it has an explicit type. No anonymous object
literals escaping a function.

```ts
// Bad
const frame = { type: 0x1, streamId: 3, data: buf };

// Good
interface HeadersFrame {
    readonly type: FrameType.HEADERS;
    readonly streamId: StreamId;
    readonly data: Uint8Array;
}
```

## 3. Never `any`

Unknown external data is `unknown`, then validated. `any` is a build failure.

```ts
function parseFrame(raw: Uint8Array): Frame {
    const unknown = decodeUnknown(raw); // unknown
    return FrameSchema.parse(unknown);  // validated → typed
}
```

## 4. Interfaces for domain objects, type aliases for states/constraints

- Interfaces for real entities (`TlsConnection`, `Http2Stream`, `Cookie`).
- Type aliases for states/constraints (`RunStatus`, `CipherSuite`).
- If values come from a known set, encode the set — never bare `string`.

## 5. Model states explicitly — make invalid states unrepresentable

No "state via nullable-field combos." Use discriminated unions.

```ts
// Bad — allows { state: "open", error: "failed" }
interface Connection {
    state: string;
    stream?: Stream;
    error?: string;
}

// Good
type ConnectionState =
    | { readonly state: "connecting" }
    | { readonly state: "open"; readonly stream: Stream }
    | { readonly state: "closed"; readonly reason: CloseReason };
```

## 6. Discriminated unions for every workflow/state

The compiler + LLM reason about every case.

## 7. Functions declare input AND output types

Public functions always define both sides — no inference-only signatures on exported APIs.

## 8. One function = one decision

No `processHandshake()` that validates + persists + schedules + notifies. Split:
`validate…`, `decodeStep`, `actuate`, `recordStep`.

## 9. No hidden behavior

A function named `updateSettings` does not also flush a log. Every side effect is its
own named call.

## 10. Name things explicitly

`cipherSuite`, `observedRank`, `clientHello` — never `data`, `result`, `obj`.
The name is the documentation.

## 11. Prefer immutable data + `readonly`

```ts
const next = { ...prev, cipherSuite } as const;
interface Connection { readonly id: ConnectionId; }
```

No in-place mutation of shared state. `const` over `let`.

## 12. Validate external data immediately

Everything from outside the boundary is `unknown`: sockets, files, captures, configs.
Use **Zod** at every boundary:

```ts
const frame = FrameSchema.parse(raw);   // never `raw as Frame`
```

## 13. Types are contracts, not documentation

```ts
// Bad   // user id
//        id: string;
// Good
type UserId = string & { __brand: "UserId" };
```

## 14. Branded/opaque ID types — load-bearing

Don't use bare `number`/`string` for IDs. This kills the "pass an X where a Y belongs"
class of bug. The project uses these brands (defined per-package, see `types.ts`):

```ts
type ConnectionId = string & { __brand: "ConnectionId" };
type StreamId     = number & { __brand: "StreamId" };
type SessionId    = string & { __brand: "SessionId" };
```

## 15. Exhaustive switches

Every `switch` over a union hits `default: assertNever(x)`. Adding a state forces every
handler to compile-error until handled.

```ts
function assertNever(x: never): never {
    throw new Error(`Unexpected value: ${JSON.stringify(x)}`);
}
```

## 16. Explicit, typed errors

```ts
// Bad
throw new Error("handshake failed");
// Good
throw new TlsHandshakeError("server_hello_parse", cause);
```

Errors are part of the API. Define them in each package's `errors.ts`.

## 17. No magic strings

`if (event === Event.COLD_START)` or a string-literal union — never bare `"cold_start"`.

## 18. Clear dependency boundaries

Domain (pure protocol logic) knows nothing of AWS / HTTP / DDB / sockets. Infrastructure
adapts. The protocol state machines stay I/O-free so they're unit-testable.

**Within this repo**, the dependency graph flows upward only — never sideways or downward:

```
@browsercore/fetch
  └─ @browsercore/http2  @browsercore/http1  @browsercore/cookies  @browsercore/profiles
        └─ @browsercore/tls
              └─ @browsercore/crypto  @browsercore/transport
                    └─ node:net / node:crypto
```

A package may only import from packages *below* it in this graph.

## 19. Documentation: why, not what

Comments explain *why* ("crawl past our position so the competitor snapshot covers the
neighborhood"), never *what* the code obviously does. Priority: Types > Names > Structure >
Comments.

## 20. API contracts in one place

Domain types live in each package's `types.ts`; wire schemas in `schemas.ts`. One source
of truth, never duplicated shapes.

---

## The Golden Rule

Every piece of important information exists as one of: **a type, a function signature,
an explicit state model, a schema validation, or clear naming.** Never rely on tribal
knowledge or hidden assumptions.
