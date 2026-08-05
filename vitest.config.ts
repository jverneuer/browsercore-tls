import { defineConfig } from "vitest/config";

// Local vitest config for @browsercore/tls. The workspace-level config measures
// coverage across every package; this narrows the scoped `--project @browsercore/tls`
// run to this package's own `src/**` so we get a clean tls-only coverage report.
export default defineConfig({
    test: {
        include: ["tests/**/*.test.ts"],
        coverage: {
            include: ["src/**"],
            provider: "v8",
            reporter: ["text", "html", "json-summary"],
            thresholds: { statements: 94, branches: 92, functions: 94, lines: 94 },
        },
    },
});
