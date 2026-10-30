// Builds Portcullis_Executive_Summary.pptx from out/report.json.
const fs = require("fs");
const path = require("path");
const pptxgen = require("pptxgenjs");
const SKILL = process.env.PPTX_SKILL_DIR;
const { applyTheme } = require(path.join(SKILL, "scripts", "apply_theme.js"));
const R = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "out", "report.json"), "utf8"));
const S = R.supply_chain, B = R.bounty, A = R.abuse, V = R.review;

const THEME = {
  name: "Portcullis", headFontFace: "Cambria", bodyFontFace: "Calibri",
  colors: { dk1: "16202E", lt1: "FFFFFF", dk2: "0B1F3F", lt2: "EEF3FA", accent1: "0B1F3F", accent2: "2F7FD6", accent3: "3B9C8E", accent4: "7F8CA3", accent5: "9FD0FF", accent6: "C24B3F", hlink: "2F7FD6", folHlink: "3B9C8E" },
};
const pres = new pptxgen();
pres.layout = "LAYOUT_16x9";
pres.title = "Portcullis Executive Summary";
pres.author = "Christian Kouadio Kouassi";
pres.theme = { headFontFace: THEME.headFontFace, bodyFontFace: THEME.bodyFontFace };
const C = pres.SchemeColor;

pres.defineSlideMaster({ title: "DARK", background: { color: C.text2 }, objects: [], slideNumber: { x: 9.2, y: 5.2, w: 0.5, h: 0.3, fontSize: 10, color: C.accent4 } });
pres.defineSlideMaster({
  title: "CONTENT", background: { color: C.background1 },
  objects: [{ placeholder: { options: { name: "title", type: "title", x: 0.6, y: 0.35, w: 8.8, h: 0.8, fontSize: 26, bold: true, color: C.text2, fontFace: "Cambria", margin: 0, valign: "top", align: "left" }, text: "" } }],
  slideNumber: { x: 9.2, y: 5.2, w: 0.5, h: 0.3, fontSize: 10, color: C.accent4 },
});
const card = (s, x, y, w, h, name, fill) => s.addShape(pres.ShapeType.roundRect, { x, y, w, h, rectRadius: 0.08, fill: { color: fill || C.background2 }, line: { color: fill || C.background2, width: 0 }, objectName: name });
const txt = (s, t, o) => s.addText(t, { margin: 0, isTextBox: true, ...o });

// 1 Title
let s = pres.addSlide({ masterName: "DARK" });
txt(s, "Portcullis", { x: 0.7, y: 1.3, w: 8.6, h: 1.0, fontFace: "Cambria", fontSize: 54, bold: true, color: C.background1, objectName: "Title" });
txt(s, "Security engineering for a Sui-style ecosystem: run the bounty, close bug classes everywhere, defend the supply chain, catch the scams", { x: 0.7, y: 2.4, w: 8.2, h: 1.1, fontSize: 20, color: C.background2, objectName: "Subtitle" });
txt(s, "Python  |  Rust  |  TypeScript  |  Move  |  Semgrep  |  Christian Kouadio Kouassi", { x: 0.7, y: 4.55, w: 8.6, h: 0.4, fontSize: 14, color: C.accent5, objectName: "Byline" });
s.addNotes("Portcullis is a portfolio project built against the Mysten Labs Security Engineer posting. It uses real public data where reachable and says plainly where data is invented.");

// 2 Headline numbers
s = pres.addSlide({ masterName: "CONTENT" });
s.addText("Checks that run on real data, with the misses left in", { placeholder: "title" });
const stats = [
  [S.npm_signatures_verified, "real npm registry signatures verified with the registry's ECDSA keys"],
  [S.npm_tarball_integrity_verified, "real tarballs match their published sha512; one flipped byte is caught"],
  [`${A.holdout.recall}`, `recall on an untuned holdout (${A.holdout.n} samples), precision ${A.holdout.precision}; one miss, listed`],
  [`${R.incidents}`, "defects found while building, each a failing test then a separate fix"],
];
stats.forEach(([big, label], i) => {
  const x = 0.6 + (i % 2) * 4.5, y = 1.4 + Math.floor(i / 2) * 1.75;
  card(s, x, y, 4.2, 1.5, `StatCard${i + 1}`);
  txt(s, big, { x: x + 0.25, y: y + 0.1, w: 3.7, h: 0.7, fontFace: "Cambria", fontSize: 36, bold: true, color: C.accent2, objectName: `StatValue${i + 1}` });
  txt(s, label, { x: x + 0.25, y: y + 0.82, w: 3.7, h: 0.62, fontSize: 13, color: C.text1, objectName: `StatLabel${i + 1}` });
});
s.addNotes("The tuned anti-scam corpus scores 1.0 because it was tuned against; only the holdout is a fair estimate.");

// 3 Modules
s = pres.addSlide({ masterName: "CONTENT" });
s.addText("Six modules map onto the six responsibilities in the posting", { placeholder: "title" });
const steps = [["Bounty", "triage, severity, SLA, budget"], ["Audit", "schedule, findings, retest"], ["Review", "Rust, TypeScript, Move"], ["Supply chain", "CI, npm, provenance"], ["Anti-scam", "domains, pages, drainers"], ["Tooling", "Semgrep rules, known-clean"]];
steps.forEach(([t, d], i) => {
  const col = i % 3, row = Math.floor(i / 3);
  const x = 0.6 + col * 3.0, y = 1.5 + row * 1.7;
  card(s, x, y, 2.7, 1.3, `Mod${i + 1}`, i === 2 ? C.accent5 : C.background2);
  s.addText([{ text: t, options: { bold: true, breakLine: true, fontSize: 16, color: C.text2 } }, { text: d, options: { fontSize: 12, color: C.text1 } }], { x: x + 0.1, y: y + 0.08, w: 2.5, h: 1.15, valign: "middle", align: "center", margin: 0, isTextBox: true, objectName: `ModText${i + 1}` });
});
txt(s, "Design rule: deterministic code decides. Report text is untrusted input and never sets severity, payout or state.", { x: 0.6, y: 4.75, w: 8.8, h: 0.4, fontSize: 12, color: C.accent4, objectName: "RuleNote" });

// 4 Supply chain chart
s = pres.addSlide({ masterName: "CONTENT" });
s.addText("Supply chain: real workflows, real compromises, real keys", { placeholder: "title" });
const rl = Object.keys(S.workflow_findings_by_rule);
s.addChart(pres.charts.BAR, [{ name: "Findings", labels: rl, values: rl.map((k) => S.workflow_findings_by_rule[k]) }],
  { x: 0.6, y: 1.3, w: 5.6, h: 3.8, barDir: "bar", chartColors: ["2F7FD6"], showLegend: false, showValue: true, dataLabelPosition: "outEnd", dataLabelFontFace: "+mn-lt", dataLabelFontSize: 11,
    catAxisLabelFontFace: "+mn-lt", catAxisLabelFontSize: 11, valAxisHidden: true, valAxisMinVal: 0, valGridLine: { style: "none" }, catGridLine: { style: "none" }, objectName: "WorkflowChart" });
card(s, 6.5, 1.4, 3.0, 3.6, "SupplyCard");
s.addText([
  { text: `${S.workflows_scanned} public workflows`, options: { bold: true, breakLine: true, color: C.text2, fontSize: 15 } },
  { text: `${S.workflows_with_no_findings.length} are clean; the rest are mostly unpinned actions. Aggregate counts, not a verdict on those projects.`, options: { breakLine: true } },
  { text: "Known-bad releases", options: { bold: true, breakLine: true, color: C.text2, fontSize: 15 } },
  { text: "debug@4.4.2, backslash@0.2.1 and color-name@2.0.1 are matched from real advisories; the real debug@4.4.3 is not.", options: {} },
], { x: 6.65, y: 1.55, w: 2.7, h: 3.4, fontSize: 11.5, color: C.text1, paraSpaceAfter: 6, valign: "top", margin: 0, isTextBox: true, objectName: "SupplyNotes" });
s.addNotes("Signed provenance uses Ed25519 over a deterministic tar with a policy check; tampering with the artifact, statement, key or commit is rejected.");

// 5 Bounty
s = pres.addSlide({ masterName: "CONTENT" });
s.addText("Bounty triage: a report cannot argue its own severity", { placeholder: "title" });
const sv = ["critical", "high", "medium", "low", "none"];
s.addChart(pres.charts.BAR, [{ name: "Unique reports", labels: ["Critical", "High", "Medium", "Low", "None"], values: sv.map((k) => B.unique_by_severity[k] || 0) }],
  { x: 0.6, y: 1.3, w: 5.4, h: 3.8, barDir: "col", chartColors: ["0B1F3F"], showLegend: false, showValue: true, dataLabelPosition: "outEnd", dataLabelFontFace: "+mn-lt", dataLabelFontSize: 12,
    catAxisLabelFontFace: "+mn-lt", catAxisLabelFontSize: 12, valAxisHidden: true, valAxisMinVal: 0, valGridLine: { style: "none" }, catGridLine: { style: "none" }, objectName: "BountyChart" });
card(s, 6.3, 1.4, 3.2, 3.6, "BountyCard");
s.addText([
  { text: `${B.reports} synthetic reports`, options: { bold: true, breakLine: true, color: C.text2, fontSize: 15 } },
  { text: `${B.duplicates} duplicates found. A report that told the triage agent to mark it critical was flagged and decided as severity none.`, options: { breakLine: true } },
  { text: "Closing the loop", options: { bold: true, breakLine: true, color: C.text2, fontSize: 15 } },
  { text: `Recurring classes (${Object.keys(B.recurring_classes).length}) become rules; fixes are accepted only if the PoC reproduces, the fix blocks it and normal input still works.`, options: {} },
], { x: 6.45, y: 1.55, w: 2.9, h: 3.4, fontSize: 11.5, color: C.text1, paraSpaceAfter: 6, valign: "top", margin: 0, isTextBox: true, objectName: "BountyNotes" });
s.addNotes("All reports are invented. No bounty platform was used. The model is a scripted stand-in: the test shows the decision ignores a drafted severity.");

// 6 Anti-scam
s = pres.addSlide({ masterName: "CONTENT" });
s.addText("Anti-scam: tuned scores look perfect, the holdout tells the truth", { placeholder: "title" });
s.addChart(pres.charts.BAR, [
  { name: "Tuned corpus", labels: ["Precision", "Recall"], values: [A.tuned_corpus.precision, A.tuned_corpus.recall] },
  { name: "Holdout", labels: ["Precision", "Recall"], values: [A.holdout.precision, A.holdout.recall] },
], { x: 0.6, y: 1.3, w: 5.4, h: 3.8, barDir: "col", barGrouping: "clustered", chartColors: ["7F8CA3", "2F7FD6"], showLegend: true, legendPos: "b", legendFontFace: "+mn-lt", legendFontSize: 12,
     showValue: true, dataLabelPosition: "outEnd", dataLabelFontFace: "+mn-lt", dataLabelFontSize: 12, dataLabelFormatCode: "0.000", catAxisLabelFontFace: "+mn-lt", catAxisLabelFontSize: 12,
     valAxisHidden: true, valAxisMinVal: 0, valAxisMaxVal: 1.15, valGridLine: { style: "none" }, catGridLine: { style: "none" }, objectName: "AbuseChart" });
card(s, 6.3, 1.4, 3.2, 3.6, "AbuseCard");
s.addText([
  { text: "Known-clean", options: { bold: true, breakLine: true, color: C.text2, fontSize: 15 } },
  { text: `Drainer detectors flagged ${A.real_sui_move_files_flagged} real Sui Move files and ${A.real_npm_js_files_flagged} real npm JavaScript files.`, options: { breakLine: true } },
  { text: "The miss", options: { bold: true, breakLine: true, color: C.text2, fontSize: 15 } },
  { text: `${A.holdout.misses.join(", ")} changes two things at once. It is documented, not hidden.`, options: {} },
], { x: 6.45, y: 1.55, w: 2.9, h: 3.4, fontSize: 11.5, color: C.text1, paraSpaceAfter: 6, valign: "top", margin: 0, isTextBox: true, objectName: "AbuseNotes" });

// 7 Incidents
s = pres.addSlide({ masterName: "CONTENT" });
s.addText("Nineteen defects, each reproduced then fixed", { placeholder: "title" });
const groups = [
  ["Seeded in Treasury (9)", "Rust panic on short frame\nRust amount truncation\nRust early-exit MAC compare\nSSRF, XSS, weak RNG, CSRF\nMove withdraw without capability\nCI workflow with four flaws"],
  ["Found by variant analysis (1)", "The SSRF fix covered one function.\nA rule derived from it found the same bug in the webhook sender."],
  ["Found by known-clean checks (2)", "Move rule flagged real sui::coin helpers\nRust rule flagged the already-fixed parser"],
  ["Found in my own tooling (7)", "YAML read on: as True\nTransposed typosquats missed\nDuplicates merged distinct bugs\nSubdomain brand, digit 1, thresholds, false positives"],
];
groups.forEach(([t, body], i) => {
  const x = 0.6 + (i % 2) * 4.5, y = 1.25 + Math.floor(i / 2) * 1.9;
  card(s, x, y, 4.3, 1.75, `Group${i + 1}`);
  txt(s, t, { x: x + 0.2, y: y + 0.1, w: 3.9, h: 0.35, fontFace: "Cambria", fontSize: 15, bold: true, color: C.accent2, objectName: `GroupTitle${i + 1}` });
  s.addText(body.split("\n").map((l, j, arr) => ({ text: l, options: { breakLine: j < arr.length - 1 } })), { x: x + 0.2, y: y + 0.48, w: 3.95, h: 1.28, fontSize: 11, color: C.text1, valign: "top", margin: 0, isTextBox: true, objectName: `GroupBody${i + 1}` });
});
txt(s, "A script re-runs every reproduce and fix commit in a clean checkout to prove it.", { x: 0.6, y: 5.17, w: 8.2, h: 0.25, fontSize: 10, color: C.accent4, objectName: "IncNote" });

// 8 Limits
s = pres.addSlide({ masterName: "DARK" });
txt(s, "What this shows, and what it does not", { x: 0.7, y: 0.5, w: 8.6, h: 0.8, fontFace: "Cambria", fontSize: 32, bold: true, color: C.background1, objectName: "ClosingTitle" });
s.addText([
  { text: "Shows", options: { bold: true, color: C.accent5, breakLine: true, fontSize: 18 } },
  { text: "Signature, hash and provenance verification on real data", options: { bullet: true, breakLine: true } },
  { text: "Bounty and audit workflows with a deterministic core", options: { bullet: true, breakLine: true } },
  { text: "Variant analysis and known-clean discipline", options: { bullet: true } },
], { x: 0.7, y: 1.5, w: 4.2, h: 2.7, fontSize: 15, color: C.background1, paraSpaceAfter: 8, valign: "top", margin: 0, isTextBox: true, objectName: "ShowsText" });
s.addText([
  { text: "Does not show", options: { bold: true, color: C.accent5, breakLine: true, fontSize: 18 } },
  { text: "Three years of real bounty or audit work, or a CVE", options: { bullet: true, breakLine: true } },
  { text: "Compiled Move: that code is pattern-checked only", options: { bullet: true, breakLine: true } },
  { text: "A live platform, wallet, chain or language model", options: { bullet: true } },
], { x: 5.2, y: 1.5, w: 4.2, h: 2.7, fontSize: 15, color: C.background1, paraSpaceAfter: 8, valign: "top", margin: 0, isTextBox: true, objectName: "NotShownText" });
txt(s, "108 tests  |  19 incidents  |  sole-author git history  |  nothing pushed", { x: 0.7, y: 4.55, w: 8.6, h: 0.4, fontSize: 14, color: C.accent3, objectName: "Footer" });

(async () => {
  const out = path.join(__dirname, "..", "Portcullis_Executive_Summary.pptx");
  await pres.writeFile({ fileName: out });
  await applyTheme(out, THEME);
  console.log("wrote", out);
})();
