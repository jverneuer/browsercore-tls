#!/usr/bin/env node
/**
 * Convert vitest's coverage-summary.json into a markdown coverage table.
 *
 * Run AFTER `vitest run --coverage` (with the json-summary reporter) so
 * coverage-summary.json exists. Writes COVERAGE.md and coverage/badge.json to
 * the current working directory (the consumer package root).
 *
 * Distributed as the `coverage-md` bin of @browsercore/dev, replacing the
 * per-repo scripts/coverage-md.mjs copies.
 *
 * Dependency-free: only node:fs + node:path. Safe in CI with no install step.
 */
import { readFileSync, writeFileSync } from "node:fs";
import { join, relative } from "node:path";

const pkgRoot = process.cwd();
const summaryPath = join(pkgRoot, "coverage", "coverage-summary.json");
const outPath = join(pkgRoot, "COVERAGE.md");
const badgePath = join(pkgRoot, "coverage", "badge.json");

/** @type {Record<string, { lines:{total:number,covered:number,pct:number}, statements:{total:number,covered:number,pct:number}, functions:{total:number,covered:number,pct:number}, branches:{total:number,covered:number,pct:number} }>} */
let data;
try {
    data = JSON.parse(readFileSync(summaryPath, "utf-8"));
} catch {
    console.error(
        `[coverage-md] Could not read ${summaryPath}. ` +
            `Run vitest with the json-summary reporter first.`,
    );
    process.exit(1);
}

const total = data.total;
/**
 * @typedef {Object} Metric
 * @property {string} label
 * @property {keyof typeof total} key
 */
/** @type {Metric[]} */
const metrics = [
    { label: "Statements", key: "statements" },
    { label: "Branches", key: "branches" },
    { label: "Functions", key: "functions" },
    { label: "Lines", key: "lines" },
];
/** @param {{pct:number,covered:number,total:number}} m */
const render = (m) => `${m.pct}% (${m.covered}/${m.total})`;

const fileEntries = Object.entries(data)
    .filter(([key]) => key !== "total")
    .map(([file, m]) => {
        // coverage-summary.json keys are absolute paths; show repo-relative.
        const rel = relative(pkgRoot, file).split("\\").join("/");
        return { file: rel, m };
    })
    .sort((a, b) => a.file.localeCompare(b.file));

const lines = [];
lines.push(`# Coverage report`);
lines.push("");
lines.push(`Generated from \`coverage-summary.json\` by \`coverage-md\` (@browsercore/dev).`);
lines.push("");
lines.push(`## Total`);
lines.push("");
lines.push(`| Metric | Coverage |`);
lines.push(`| --- | --- |`);
for (const { label, key } of metrics) {
    lines.push(`| ${label} | ${render(total[key])} |`);
}
lines.push("");
lines.push(`## Per-file`);
lines.push("");
const header = `| File | ${metrics.map((m) => m.label).join(" | ")} |`;
const sep = `| --- | ${metrics.map(() => "---").join(" | ")} |`;
lines.push(header);
lines.push(sep);
for (const { file, m } of fileEntries) {
    lines.push(`| \`${file}\` | ${metrics.map((met) => render(m[met.key])).join(" | ")} |`);
}
lines.push("");

writeFileSync(outPath, lines.join("\n"));
console.log(`[coverage-md] wrote ${relative(process.cwd(), outPath)}`);

// shields.io endpoint badge: a single coverage figure (statements %) for the
// README badge. Color tiers mirror shields.io conventions.
const pct = total.statements.pct;
const badgeColor =
    pct >= 90 ? "brightgreen" : pct >= 75 ? "green" : pct >= 50 ? "yellow" : "red";
const badge = {
    schemaVersion: 1,
    label: "coverage",
    message: `${pct}%`,
    color: badgeColor,
    namedLogo: "vitest",
};
writeFileSync(badgePath, JSON.stringify(badge));
console.log(`[coverage-md] wrote ${relative(process.cwd(), badgePath)}`);
