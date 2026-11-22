// Benchmark evaluation shared by `npm run benchmark` (run.js) and the regression test.
// Scores every message with score(text) only: no AI score (l3Score) and no Safe Browsing (l2Hit).

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { score } from "../src/index.js";
import { BENCHMARK_DETECTED_MIN_SCORE, BENCHMARK_STRONG_MIN_SCORE } from "../src/config.js";

export const SETS = Object.freeze(["dev", "heldout"]);
export const BENCHMARK_DIR = dirname(fileURLToPath(import.meta.url));

/** @returns {Array<{ id: string, text: string, label: "scam" | "benign", category: string }>} */
export function loadSet(name) {
  if (!SETS.includes(name)) throw new Error(`unknown set "${name}", expected one of: ${SETS.join(", ")}`);
  return JSON.parse(readFileSync(join(BENCHMARK_DIR, `${name}.json`), "utf8"));
}

const rate = (n, d) => (d === 0 ? 0 : n / d);

export function evaluate(messages) {
  const rows = messages.map((m) => {
    const r = score(m.text);
    return { ...m, riskScore: r.riskScore, verdict: r.verdict, flags: r.redFlags.map((f) => f.id) };
  });
  const scams = rows.filter((r) => r.label === "scam");
  const benign = rows.filter((r) => r.label === "benign");

  const counts = {};
  for (const r of rows) {
    counts[r.label] ??= { pookie: 0, skeptical: 0, poltergeist: 0, total: 0 };
    counts[r.label][r.verdict]++;
    counts[r.label].total++;
  }

  const detected = scams.filter((r) => r.riskScore >= BENCHMARK_DETECTED_MIN_SCORE);
  const strong = scams.filter((r) => r.riskScore >= BENCHMARK_STRONG_MIN_SCORE);
  const falseAlarms = benign.filter((r) => r.riskScore >= BENCHMARK_DETECTED_MIN_SCORE);

  const perCategory = {};
  for (const r of scams) {
    perCategory[r.category] ??= { total: 0, detected: 0, strong: 0 };
    perCategory[r.category].total++;
    if (r.riskScore >= BENCHMARK_DETECTED_MIN_SCORE) perCategory[r.category].detected++;
    if (r.riskScore >= BENCHMARK_STRONG_MIN_SCORE) perCategory[r.category].strong++;
  }

  return {
    rows,
    counts,
    detectionRate: rate(detected.length, scams.length),
    strongDetectionRate: rate(strong.length, scams.length),
    falseAlarmRate: rate(falseAlarms.length, benign.length),
    detected: detected.length,
    strong: strong.length,
    scams: scams.length,
    benign: benign.length,
    perCategory,
    misses: scams.filter((r) => r.riskScore < BENCHMARK_DETECTED_MIN_SCORE),
    falseAlarms,
  };
}

const pct = (x) => `${(x * 100).toFixed(1)}%`;
const oneLine = (s, max = 90) => {
  const t = s.replace(/\s+/g, " ");
  return t.length > max ? `${t.slice(0, max - 1)}…` : t;
};

/** Plain-text report for the terminal. */
export function formatText(name, ev) {
  const lines = [];
  lines.push(`Benchmark set: ${name} (${ev.rows.length} messages, score(text) only: no AI, no Safe Browsing)`);
  lines.push("");
  lines.push("label    pookie  skeptical  poltergeist  total");
  for (const label of ["scam", "benign"]) {
    const c = ev.counts[label] ?? { pookie: 0, skeptical: 0, poltergeist: 0, total: 0 };
    lines.push(
      `${label.padEnd(8)} ${String(c.pookie).padStart(6)}  ${String(c.skeptical).padStart(9)}  ` +
        `${String(c.poltergeist).padStart(11)}  ${String(c.total).padStart(5)}`,
    );
  }
  lines.push("");
  lines.push(`Detection rate (scam >= ${BENCHMARK_DETECTED_MIN_SCORE}):       ${pct(ev.detectionRate)} (${ev.detected}/${ev.scams})`);
  lines.push(`Strong detection rate (scam >= ${BENCHMARK_STRONG_MIN_SCORE}): ${pct(ev.strongDetectionRate)} (${ev.strong}/${ev.scams})`);
  lines.push(
    `False-alarm rate (benign >= ${BENCHMARK_DETECTED_MIN_SCORE}):  ${pct(ev.falseAlarmRate)} (${ev.falseAlarms.length}/${ev.benign})`,
  );
  lines.push("");
  lines.push("category                       detected  strong  total");
  for (const [cat, c] of Object.entries(ev.perCategory).sort()) {
    lines.push(`${cat.padEnd(30)} ${String(c.detected).padStart(8)}  ${String(c.strong).padStart(6)}  ${String(c.total).padStart(5)}`);
  }
  lines.push("");
  lines.push(`Misses (${ev.misses.length}):`);
  for (const r of ev.misses) lines.push(`  ${r.id} [${r.riskScore}] ${r.category}: ${oneLine(r.text)}`);
  lines.push(`False alarms (${ev.falseAlarms.length}):`);
  for (const r of ev.falseAlarms) lines.push(`  ${r.id} [${r.riskScore}] ${r.category}: ${oneLine(r.text)}`);
  return lines.join("\n");
}

const mdCell = (s) => s.replace(/\|/g, "\\|");

/** Markdown section for RESULTS.md. */
export function formatMarkdown(name, ev, date) {
  const lines = [];
  lines.push(`## Set: ${name}`);
  lines.push("");
  lines.push(`Run on ${date} with \`score(text)\` only (no AI, no Safe Browsing). ${ev.rows.length} messages.`);
  lines.push("");
  lines.push("| Metric | Value |");
  lines.push("|---|---|");
  lines.push(`| Detection rate (scam scored >= ${BENCHMARK_DETECTED_MIN_SCORE}) | ${pct(ev.detectionRate)} (${ev.detected}/${ev.scams}) |`);
  lines.push(`| Strong detection rate (scam scored >= ${BENCHMARK_STRONG_MIN_SCORE}) | ${pct(ev.strongDetectionRate)} (${ev.strong}/${ev.scams}) |`);
  lines.push(
    `| False-alarm rate (benign scored >= ${BENCHMARK_DETECTED_MIN_SCORE}) | ${pct(ev.falseAlarmRate)} (${ev.falseAlarms.length}/${ev.benign}) |`,
  );
  lines.push("");
  lines.push("| Label | Pookie | Skeptical | Poltergeist | Total |");
  lines.push("|---|---|---|---|---|");
  for (const label of ["scam", "benign"]) {
    const c = ev.counts[label] ?? { pookie: 0, skeptical: 0, poltergeist: 0, total: 0 };
    lines.push(`| ${label} | ${c.pookie} | ${c.skeptical} | ${c.poltergeist} | ${c.total} |`);
  }
  lines.push("");
  lines.push("| Scam category | Detected | Strong | Total |");
  lines.push("|---|---|---|---|");
  for (const [cat, c] of Object.entries(ev.perCategory).sort()) {
    lines.push(`| ${cat} | ${c.detected} | ${c.strong} | ${c.total} |`);
  }
  lines.push("");
  lines.push(`Misses (${ev.misses.length}):`);
  lines.push("");
  for (const r of ev.misses) lines.push(`- \`${r.id}\` (${r.riskScore}, ${r.category}): ${mdCell(oneLine(r.text, 140))}`);
  if (ev.misses.length === 0) lines.push("- none");
  lines.push("");
  lines.push(`False alarms (${ev.falseAlarms.length}):`);
  lines.push("");
  for (const r of ev.falseAlarms) lines.push(`- \`${r.id}\` (${r.riskScore}, ${r.category}): ${mdCell(oneLine(r.text, 140))}`);
  if (ev.falseAlarms.length === 0) lines.push("- none");
  return lines.join("\n");
}
