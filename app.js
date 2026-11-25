// Connects the page to the WebCyb detector.
// Uses textContent everywhere, so pasted text is never run as code.
const form = document.getElementById("check-form");
const box = document.getElementById("results-box");
const errorEl = document.getElementById("error");

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, v);
  node.append(...children);
  return node;
}

form.addEventListener("submit", event => {
  event.preventDefault();
  const text = document.getElementById("email").value.trim();
  errorEl.textContent = "";
  if (!text) { errorEl.textContent = "Please paste the email you received first."; return; }
  if (text.length < 15) { errorEl.textContent = "That's very short. Please paste the whole email."; return; }

  const r = WebCyb.analyze(text);
  const headline = { Phishing: "This email is likely phishing", Suspicious: "This email looks suspicious",
                     "Likely safe": "This email looks safe" }[r.verdict];

  const meter = el("div", { class: "meter", role: "img", "aria-label": `Risk score ${r.score} out of 100` }, el("span"));
  meter.firstChild.style.width = r.score + "%";

  const vulnList = r.groups.length
    ? el("ul", { class: "vulns" }, ...r.groups.map(g =>
        el("li", {}, el("span", { class: "vuln-name" }, g.category, " ", el("span", { class: "pts" }, `(+${g.points})`)),
          el("ul", {}, ...g.details.map(d => el("li", {}, d))))))
    : el("p", {}, "No vulnerabilities found. WebCyb didn't detect common phishing signs.");

  box.className = "results-box level-" + r.level.toLowerCase();
  box.replaceChildren(
    el("div", { class: "verdict-row" }, el("p", { class: "verdict" }, headline),
      el("p", { class: "risk" }, `Risk level: ${r.level} · Score ${r.score}/100`)),
    meter,
    el("h3", {}, "WebCyb says"),
    el("p", { class: "says" }, r.reply),
    el("h3", {}, `Vulnerabilities found (${r.groups.length})`),
    vulnList,
    el("h3", {}, "What you should do"),
    el("ul", { class: "advice" }, ...r.advice.map(a => el("li", {}, a))),
  );
  box.scrollIntoView({ behavior: "smooth", block: "start" });
});
