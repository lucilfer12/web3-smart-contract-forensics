const el = (id) => document.getElementById(id);
let data = [];

function node(tag, text, className) {
  const n = document.createElement(tag);
  if (className) n.className = className;
  n.textContent = text;
  return n;
}

function render() {
  const q = el("q").value.toLowerCase().trim();
  const type = el("type").value;
  const rows = data.filter((x) =>
    (!q || [x.title, x.project, x.vulnerability_class, x.source_name].join(" ").toLowerCase().includes(q)) &&
    (!type || x.record_type === type)
  );

  const stats = el("stats");
  stats.replaceChildren();
  [["Records", data.length], ["Critical", data.filter((x) => x.severity === "Critical").length],
   ["Bounties", data.filter((x) => x.reward_amount != null).length]].forEach(([label, value]) => {
    const card = node("div", "", "stat");
    card.append(node("b", String(value)));
    card.append(node("div", label, "muted"));
    stats.append(card);
  });

  const results = el("results");
  results.replaceChildren();
  rows.slice(0, 100).forEach((x) => {
    const article = node("article", "", "card");
    article.append(node("div", `${x.case_id} — ${x.title}`, "title"));
    const meta = node("div", "", "meta");
    meta.append(node("span", x.record_type, "tag"));
    meta.append(node("span", "Critical", "tag"));
    if (x.project) meta.append(node("span", x.project, "tag"));
    if (x.reward_amount) meta.append(node("span", `$${Number(x.reward_amount).toLocaleString()}`, "tag"));
    article.append(meta);
    article.append(node("p", x.vulnerability_class || "Class pending normalization", "muted"));
    results.append(article);
  });
}

fetch("../datasets/reports.json").then((r) => r.json()).then((x) => { data = x; render(); });
["q", "type"].forEach((id) => el(id).addEventListener("input", render));
