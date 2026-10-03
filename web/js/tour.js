/* AegisTour — first-visit guided tour. 4 steps, overlay card,
 * "Show me" scrolls to the section, skippable, "don't show again"
 * persisted in localStorage. */
window.AegisTour = (() => {
  "use strict";
  const KEY = "aegis_tour_seen_v1";

  const STEPS = [
    {
      title: "Threats never sleep",
      body: "Every public system is probed thousands of times a day by automated scanners. Most of it is noise \u2014 but buried in it are real attacks, arriving at 3am on a Sunday.",
      target: "#why",
      cta: "Show me the noise",
    },
    {
      title: "Twelve engines watch",
      body: "Each engine does one job well: lookalike domains, DNS drift, login attacks, leaked secrets, cloud misconfig, and seven more. They run around the clock and never get tired.",
      target: "#engines",
      cta: "Meet the engines",
    },
    {
      title: "Findings get scored, stitched into cases",
      body: "Raw alerts are noise. Aegis scores each finding against asset criticality, dedupes repeats, and correlates findings that share an entity into one case \u2014 an attack chain, not a pile of alerts.",
      target: "#pipeline",
      cta: "See the pipeline",
    },
    {
      title: "Playbooks respond automatically",
      body: "A case triggers a response playbook: block, revoke, reset, takedown. On autopilot it just happens; in manual mode you approve each step. Run one below.",
      target: "#simulator",
      cta: "Run an attack",
    },
  ];

  let idx = 0;
  let overlay = null;

  function build() {
    overlay = document.createElement("div");
    overlay.className = "tour-overlay";
    overlay.innerHTML =
      '<div class="tour-card" role="dialog" aria-modal="true" aria-label="Guided tour">' +
      '<p class="tour-kicker"><span class="tour-step-no"></span> / 4 \u2014 First visit</p>' +
      '<h3 class="tour-title"></h3>' +
      '<p class="tour-body"></p>' +
      '<div class="tour-actions">' +
      '<button class="btn-primary tour-show">Show me</button>' +
      '<button class="btn-ghost tour-next">Next</button>' +
      '<button class="btn-ghost tour-skip">Skip tour</button>' +
      "</div>" +
      '<label class="tour-again"><input type="checkbox" class="tour-again-box"> Don\u2019t show this again</label>' +
      "</div>";
    document.body.appendChild(overlay);
    overlay.querySelector(".tour-show").addEventListener("click", showTarget);
    overlay.querySelector(".tour-next").addEventListener("click", next);
    overlay.querySelector(".tour-skip").addEventListener("click", close);
    overlay.addEventListener("click", (e) => {
      if (e.target === overlay) close();
    });
    document.addEventListener("keydown", onKey);
    overlay.querySelector(".tour-again-box").addEventListener("change", (e) => {
      if (e.target.checked) {
        try {
          localStorage.setItem(KEY, "1");
        } catch (err) {}
      }
    });
  }

  function render() {
    const s = STEPS[idx];
    overlay.querySelector(".tour-step-no").textContent = String(idx + 1);
    overlay.querySelector(".tour-title").textContent = s.title;
    overlay.querySelector(".tour-body").textContent = s.body;
    overlay.querySelector(".tour-next").textContent =
      idx === STEPS.length - 1 ? "Finish" : "Next";
  }

  function showTarget() {
    const s = STEPS[idx];
    const el = document.querySelector(s.target);
    if (el) el.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  function next() {
    if (idx >= STEPS.length - 1) {
      close();
      return;
    }
    idx += 1;
    render();
  }

  function close() {
    try {
      localStorage.setItem(KEY, "1");
    } catch (err) {}
    const el = overlay;
    overlay = null;
    if (el) {
      el.classList.remove("tour-visible");
      el.classList.add("tour-leaving");
      setTimeout(() => el.remove(), 300);
    }
    document.removeEventListener("keydown", onKey);
  }

  function onKey(e) {
    if (e.key === "Escape") close();
  }

  function shouldShow() {
    try {
      return !localStorage.getItem(KEY);
    } catch (err) {
      return true;
    }
  }

  return {
    start() {
      if (overlay) return;
      idx = 0;
      build();
      render();
      requestAnimationFrame(() => overlay.classList.add("tour-visible"));
    },
    maybeShow() {
      if (shouldShow()) {
        setTimeout(() => this.start(), 1200);
      }
    },
  };
})();
