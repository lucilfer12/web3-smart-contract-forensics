const el = (id) => document.getElementById(id);
let data = [];
let audits = [];
const RULE_COUNT = 13;

function node(tag, text, className) {
  const n = document.createElement(tag);
  if (className) n.className = className;
  if (text !== undefined) n.textContent = text;
  return n;
}

function renderStats() {
  const stats = el("stats");
  stats.replaceChildren();
  [["Research records", data.length], ["Structured audit reports", audits.length], ["Built-in engine rules", RULE_COUNT], ["Engine status", "Runnable"]].forEach(([label, value]) => {
    const card = node("div", "", "card stat");
    card.append(node("b", String(value)));
    card.append(node("div", label, "muted"));
    stats.append(card);
  });
}

function render() {
  renderStats();
  const q = el("q").value.toLowerCase().trim();
  const type = el("type").value;
  const rows = data.filter((x) => (!q || [x.title, x.project, x.vulnerability_class, x.source_name].join(" ").toLowerCase().includes(q)) && (!type || x.record_type === type));
  const results = el("results");
  results.replaceChildren();
  rows.slice(0, 100).forEach((x) => {
    const article = node("article", "", "result");
    article.append(node("div", String(x.case_id) + " — " + String(x.title), "title"));
    const meta = node("div", "", "meta");
    meta.append(node("span", x.record_type || "record", "tag"));
    meta.append(node("span", x.severity || "unknown", "tag"));
    if (x.project) meta.append(node("span", x.project, "tag"));
    article.append(meta);
    article.append(node("p", x.vulnerability_class || "Class pending normalization", "muted"));
    results.append(article);
  });
}

Promise.all([
  fetch("../datasets/reports.json").then((r) => r.json()),
  fetch("../datasets/audit_reports.json").then((r) => r.json())
])
  .then(([legacy, audit]) => { data = legacy; audits = audit; render(); })
  .catch((error) => { el("results").append(node("p", "Unable to load corpus: " + error, "muted")); });

["q", "type"].forEach((id) => el(id).addEventListener("input", render));
