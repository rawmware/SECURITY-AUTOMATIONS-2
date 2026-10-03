/* app.js — boots the Aegis demo: nav, engine grid, findings feed,
 * ticker, scenario runner, playbook execution, pipeline trace,
 * section reveals, ambient background-radiation loop. */
(() => {
  "use strict";

  const $ = (s, r) => (r || document).querySelector(s);
  const $$ = (s, r) => Array.from((r || document).querySelectorAll(s));
  const wait = (ms) => new Promise((res) => setTimeout(res, ms));
  const esc = (s) =>
    String(s).replace(/[&<>"']/g, (c) => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
    }[c]));
  const clock = () => new Date().toTimeString().slice(0, 8);

  const Sim = window.AegisSim;
  const ENGINES = window.AEGIS_ENGINES;
  const SCENARIOS = window.AEGIS_SCENARIOS;
  const REPO = "https://github.com/rawmware/SECURITY-AUTOMATIONS-2";

  let scene = null;
  let running = false;
  let selectedScenario = SCENARIOS[0];
  let autopilot = true;

  /* ---------- nav ---------- */
  function initNav() {
    const links = $$(".nav-link");
    const sections = links
      .map((l) => $(l.getAttribute("href")))
      .filter(Boolean);
    const io = new IntersectionObserver(
      (entries) => {
        entries.forEach((e) => {
          if (e.isIntersecting) {
            links.forEach((l) =>
              l.classList.toggle("active", l.getAttribute("href") === "#" + e.target.id)
            );
          }
        });
      },
      { rootMargin: "-40% 0px -55% 0px" }
    );
    sections.forEach((s) => io.observe(s));
  }

  /* ---------- reveal on scroll ---------- */
  function initReveal() {
    const io = new IntersectionObserver(
      (entries) => {
        entries.forEach((e) => {
          if (e.isIntersecting) {
            e.target.classList.add("visible");
            io.unobserve(e.target);
          }
        });
      },
      { threshold: 0.12 }
    );
    $$(".reveal").forEach((el) => io.observe(el));
  }

  /* ---------- engine grid + detail ---------- */
  const SEV_COLORS = {
    critical: "#E5484D", high: "#E8A33D", medium: "#E8A33D",
    low: "#8A8F98", informational: "#8A8F98",
  };

  function initEngines() {
    const grid = $("#engine-grid");
    grid.innerHTML = ENGINES.map(
      (e) =>
        '<button class="engine-card" data-engine="' + e.id + '">' +
        '<span class="engine-count" data-count="' + e.id + '">0</span>' +
        '<span class="engine-name">' + esc(e.name) + "</span>" +
        '<span class="engine-tag">' + esc(e.tagline) + "</span>" +
        "</button>"
    ).join("");
    grid.addEventListener("click", (ev) => {
      const card = ev.target.closest(".engine-card");
      if (card) selectEngine(card.dataset.engine);
    });
    selectEngine(ENGINES[0].id);
  }

  function selectEngine(id) {
    const e = ENGINES.find((x) => x.id === id);
    if (!e) return;
    $$(".engine-card").forEach((c) =>
      c.classList.toggle("selected", c.dataset.engine === id)
    );
    $("#engine-detail").innerHTML =
      '<p class="kicker">Engine \u2014 ' + esc(e.id) + "</p>" +
      '<h3 class="detail-name">' + esc(e.name) + "</h3>" +
      '<p class="detail-tagline">' + esc(e.tagline) + "</p>" +
      '<p class="detail-plain">' + esc(e.plainEnglish) + "</p>" +
      '<p class="detail-technique"><span class="mono-label">Technique</span>' + esc(e.technique) + "</p>" +
      '<div class="detail-codehead"><span class="mono-label">' + esc(e.repoPath) + "</span></div>" +
      '<pre class="code"><code>' + esc(e.snippet) + "</code></pre>" +
      '<a class="detail-link" href="' + REPO + "/blob/main/" + esc(e.repoPath) + '" target="_blank" rel="noopener">' +
      "Read the real implementation \u2192</a>";
  }

  /* ---------- findings feed + ticker ---------- */
  const tickerItems = [];
  function addFinding(f, opts) {
    opts = opts || {};
    const feed = $("#findings-feed");
    const div = document.createElement("div");
    div.className = "finding" + (opts.ambient ? " ambient" : "");
    div.innerHTML =
      '<span class="sev-dot" style="background:' + SEV_COLORS[f.severity] + '"></span>' +
      '<div class="finding-main">' +
      '<div class="finding-title">' + esc(f.title) + "</div>" +
      '<div class="finding-meta"><span class="mono">' + esc(f.engine) + "</span>" +
      "<span>score " + f.adjustedScore.toFixed(1) + " \u00b7 " + esc(f.adjustedSeverity) + "</span>" +
      "<span>" + clock() + "</span></div></div>";
    feed.prepend(div);
    while (feed.children.length > 40) feed.lastChild.remove();

    const badge = document.querySelector('[data-count="' + f.engine + '"]');
    if (badge) badge.textContent = String(Sim.counters[f.engine] || 0);

    if (!opts.ambient) {
      tickerItems.unshift(f.engine + ": " + f.title);
      if (tickerItems.length > 8) tickerItems.pop();
      renderTicker();
    }
  }

  function renderTicker() {
    const text = tickerItems.length
      ? tickerItems.join("  \u2003///\u2003  ")
      : "AEGIS OPS \u2003///\u2003 all engines nominal \u2003///\u2003 waiting for events";
    const inner = $("#ticker-inner");
    inner.innerHTML =
      "<span>" + esc(text) + "</span><span>" + esc(text) + "</span>";
  }

  /* ---------- threat meter ---------- */
  let threatShown = 12;
  function bumpThreat(v) {
    threatShown = Math.max(0, Math.min(100, threatShown + v));
    paintThreat();
  }
  function paintThreat() {
    const fill = $("#threat-fill");
    if (!fill) return;
    fill.style.width = threatShown + "%";
    fill.style.background =
      threatShown >= 70 ? "#E5484D" : threatShown >= 40 ? "#E8A33D" : "#46A758";
    $("#threat-label").textContent =
      threatShown >= 70 ? "elevated" : threatShown >= 40 ? "active" : "nominal";
  }

  /* ---------- scenario picker + run ---------- */
  function initSimulator() {
    const grid = $("#scenario-grid");
    grid.innerHTML = SCENARIOS.map(
      (s, i) =>
        '<button class="scenario-card' + (i === 0 ? " selected" : "") + '" data-scenario="' + s.id + '">' +
        '<span class="scenario-title">' + esc(s.title) + "</span>" +
        '<span class="scenario-threat">' + esc(s.threat) + "</span>" +
        '<span class="scenario-meta mono">' + s.timeline.length + " events \u00b7 ~20s</span>" +
        "</button>"
    ).join("");
    grid.addEventListener("click", (ev) => {
      const card = ev.target.closest(".scenario-card");
      if (!card || running) return;
      selectedScenario = SCENARIOS.find((s) => s.id === card.dataset.scenario);
      $$(".scenario-card").forEach((c) =>
        c.classList.toggle("selected", c === card)
      );
      renderPlaybookIntro();
    });

    $("#run-btn").addEventListener("click", () => runScenario(selectedScenario));
    const ap = $("#autopilot-toggle");
    ap.addEventListener("change", () => {
      autopilot = ap.checked;
      $("#autopilot-state").textContent = autopilot ? "on" : "off";
    });
    renderPlaybookIntro();
  }

  function renderPlaybookIntro() {
    const pb = selectedScenario.playbook;
    $("#playbook-panel").innerHTML =
      '<p class="kicker">Response playbook</p>' +
      '<h3 class="playbook-name">' + esc(pb.name) + "</h3>" +
      '<p class="playbook-hint">Run the scenario above and this playbook ' +
      (autopilot
        ? "executes each step automatically."
        : "waits for your approval on each step.") +
      "</p>" +
      '<ol class="playbook-steps">' +
      pb.steps.map((s) => '<li class="pb-step pending"><span>' + esc(s) + "</span></li>").join("") +
      "</ol>";
    $("#case-banner").innerHTML = "";
  }

  async function runScenario(sc) {
    if (running) return;
    running = true;
    $("#run-btn").disabled = true;
    $("#run-btn").textContent = "Running\u2026";
    $("#case-banner").innerHTML = "";
    $("#sim-status").textContent = "attack in progress";
    document.querySelector("#ops").scrollIntoView({ behavior: "smooth" });
    await wait(600);

    scene.setThreatLevel(0.35);
    bumpThreat(18);
    const targetHits = {};
    const fresh = [];
    const t0 = performance.now();

    for (const ev of sc.timeline) {
      const elapsed = performance.now() - t0;
      if (ev.t > elapsed) await wait(ev.t - elapsed);
      const f = Sim.makeFinding(ev.engine, ev);
      const scored = Sim.adjustScore(f, "high");
      const { fresh: ok } = Sim.dedupe([scored]);
      ok.forEach((x) => {
        Sim.emit("finding", x);
        addFinding(x);
        fresh.push(x);
      });
      scene.attack(ev.viz.target, ev.viz.kind);
      bumpThreat(ev.viz.kind === "probe" ? 2 : 5);
      targetHits[ev.viz.target] = (targetHits[ev.viz.target] || 0) + 1;
    }

    /* correlation */
    await wait(700);
    const cases = Sim.correlate(fresh);
    const topTarget = Object.entries(targetHits).sort((a, b) => b[1] - a[1])[0];
    cases.forEach((c) => {
      const banner = document.createElement("div");
      banner.className = "case-banner";
      banner.innerHTML =
        '<p class="case-kicker">' + c.findings.length + " findings stitched into 1 case</p>" +
        '<h4 class="case-title">' + esc(c.title) + ' <span class="mono sev-' + c.severity + '">' + esc(c.severity) + " \u00b7 " + c.score.toFixed(0) + "</span></h4>" +
        '<p class="case-narrative">' + esc(c.narrative) + "</p>";
      $("#case-banner").appendChild(banner);
    });
    if (topTarget) scene.shield(topTarget[0]);
    scene.setThreatLevel(0.9);
    bumpThreat(10);
    $("#sim-status").textContent = cases.length
      ? cases.length + " case(s) open \u2014 responding"
      : "responding";

    /* playbook */
    await runPlaybook(sc.playbook);

    scene.setThreatLevel(0.18);
    bumpThreat(-35);
    $("#sim-status").textContent = "nominal";
    $("#run-btn").disabled = false;
    $("#run-btn").textContent = "Run scenario";
    running = false;
  }

  async function runPlaybook(pb) {
    const panel = $("#playbook-panel");
    panel.innerHTML =
      '<p class="kicker">Response playbook</p>' +
      '<h3 class="playbook-name">' + esc(pb.name) + "</h3>" +
      '<ol class="playbook-steps" id="pb-live">' +
      pb.steps.map((s) => '<li class="pb-step pending"><span>' + esc(s) + "</span></li>").join("") +
      "</ol>";
    const items = $$("#pb-live .pb-step");
    for (let i = 0; i < items.length; i++) {
      const li = items[i];
      li.classList.remove("pending");
      li.classList.add("active");
      if (autopilot) {
        await wait(750);
        li.classList.remove("active");
        li.classList.add("done");
      } else {
        const decision = await askApproval(li);
        li.classList.remove("active");
        li.classList.add(decision);
      }
    }
  }

  function askApproval(li) {
    return new Promise((resolve) => {
      const box = document.createElement("div");
      box.className = "pb-decide";
      box.innerHTML =
        '<button class="btn-approve">Approve</button>' +
        '<button class="btn-deny">Deny</button>';
      li.appendChild(box);
      box.querySelector(".btn-approve").addEventListener("click", () => {
        box.remove();
        resolve("done");
      });
      box.querySelector(".btn-deny").addEventListener("click", () => {
        box.remove();
        resolve("denied");
      });
    });
  }

  /* ---------- pipeline trace ---------- */
  const STAGES = [
    ["normalize", "Raw input becomes a finding: entities extracted, timestamps fixed."],
    ["enrich", "Context attached: domain age, ASN, asset owner, past sightings."],
    ["score", "Base score \u00d7 asset criticality \u2192 adjusted score and severity."],
    ["correlate", "Findings sharing an entity are stitched into one case."],
    ["dedupe", "Already-seen fingerprints are dropped before anyone is paged."],
    ["alert", "The case is routed: channel, severity, and who owns it."],
    ["respond", "A playbook fires \u2014 block, revoke, reset \u2014 automatically or on approval."],
  ];

  function initPipeline() {
    $("#pipeline-stages").innerHTML = STAGES.map(
      (s, i) =>
        '<div class="stage" id="stage-' + s[0] + '">' +
        '<span class="stage-no mono">' + String(i + 1).padStart(2, "0") + "</span>" +
        '<span class="stage-name">' + s[0] + "</span>" +
        '<span class="stage-desc">' + s[1] + "</span>" +
        '<span class="stage-value mono"></span></div>' +
        (i < STAGES.length - 1 ? '<div class="stage-arrow">\u2192</div>' : "")
    ).join("");
    $("#trace-btn").addEventListener("click", traceFinding);
  }

  async function traceFinding() {
    const btn = $("#trace-btn");
    if (btn.disabled) return;
    btn.disabled = true;
    const log = $("#trace-log");
    log.innerHTML = "";
    $$(".stage").forEach((s) => {
      s.classList.remove("lit");
      $(".stage-value", s).textContent = "";
    });

    const line = (t) => {
      const p = document.createElement("p");
      p.className = "trace-line";
      p.textContent = t;
      log.appendChild(p);
      log.scrollTop = log.scrollHeight;
    };
    const lit = (id, value) => {
      const el = $("#stage-" + id);
      el.classList.add("lit");
      $(".stage-value", el).textContent = value;
      el.scrollIntoView({ behavior: "smooth", block: "nearest" });
    };

    /* one finding, walked through the real pipeline functions */
    const f = Sim.makeFinding("typo_watch", {
      title: "Lookalike domain live: harborlinebank-secure.com",
      score: 78,
      entities: { domain: "harborline-bank.com", lookalikes: ["harborlinebank-secure.com"] },
      evidence: { techniques: ["omission"] },
    });
    await wait(400);
    lit("normalize", "entities: domain, lookalikes");
    line("[normalize] entities extracted \u2014 domain=harborline-bank.com, 1 lookalike");
    await wait(900);

    lit("enrich", "+ age 6h \u00b7 + MX live \u00b7 + owner: brand-team");
    line("[enrich] domain age 6h \u00b7 MX records live \u00b7 asset owner: brand-team");
    await wait(900);

    const scored = Sim.adjustScore(f, "high");
    lit("score", f.score.toFixed(1) + " \u00d7 1.15 \u2192 " + scored.adjustedScore.toFixed(1) + " " + scored.adjustedSeverity);
    line("[score] " + f.score.toFixed(1) + " \u00d7 1.15 (high-value asset) = " + scored.adjustedScore.toFixed(1) + " \u2192 " + scored.adjustedSeverity);
    await wait(900);

    const f2 = Sim.makeFinding("phish_kit", {
      title: "Phishing kit at harborlinebank-secure.com", score: 91,
      entities: { url: "harborlinebank-secure.com", kit: "HarborPhish v3" }, evidence: {},
    });
    const cases = Sim.correlate([scored, Sim.adjustScore(f2, "high")]);
    lit("correlate", cases.length ? "1 case \u00b7 2 findings \u00b7 shared entity" : "no links");
    line("[correlate] " + (cases.length ? "2 findings share 'harborlinebank-secure.com' \u2192 1 case: " + cases[0].title : "no shared entities"));
    await wait(900);

    const { fresh, dups } = Sim.dedupe([scored]);
    lit("dedupe", "fp " + scored.fingerprint.slice(0, 8) + " \u00b7 " + (fresh.length ? "new" : "dup x" + (dups.length + 1)));
    line("[dedupe] fingerprint " + scored.fingerprint + " \u2014 " + (fresh.length ? "never seen, passes through" : "already seen, dropped"));
    await wait(900);

    lit("alert", "#security \u00b7 high \u00b7 owner: brand-team");
    line("[alert] routed to #security \u2014 severity high, owner brand-team");
    await wait(900);

    lit("respond", "playbook: brand-impersonation-takedown");
    line("[respond] playbook 'brand-impersonation-takedown' armed \u2014 5 steps");
    line("done. 7 stages, one finding, zero human triage.");
    btn.disabled = false;
  }

  /* ---------- ambient loop ---------- */
  function initAmbient() {
    setInterval(() => {
      if (document.hidden) return;
      const f = Sim.ambientTick();
      if (f) addFinding(f, { ambient: true });
      if (scene) scene.decayThreat();
      threatShown = Math.max(8, threatShown - 1);
      paintThreat();
    }, 2500);
  }

  /* ---------- boot ---------- */
  function boot() {
    initNav();
    initReveal();
    initEngines();
    initSimulator();
    initPipeline();
    renderTicker();
    paintThreat();

    const cta = $("#cta-watch");
    if (cta) cta.addEventListener("click", () => window.AegisTour.start());

    try {
      scene = window.AegisScene($("#scene"));
    } catch (e) {
      $("#scene").outerHTML =
        '<div class="scene-fallback"><p>3D view needs WebGL. Everything else on this page works without it.</p></div>';
      /* no-op stub so scenario runs never touch a null scene */
      scene = {
        attack() {}, shield() {}, pulse() {}, setThreatLevel() {},
        decayThreat() {}, resize() {}, nodeIds: [],
      };
    }

    Sim.on("finding", () => {});
    window.AegisROI.init();
    window.AegisTour.maybeShow();
    initAmbient();

    /* seed the feed with a couple of ambient findings so it isn't empty */
    setTimeout(() => {
      const a = Sim.ambientTick(1);
      if (a) addFinding(a, { ambient: true });
    }, 800);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }
})();
