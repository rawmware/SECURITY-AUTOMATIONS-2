/* AegisROI — honest back-of-envelope calculator.
 * Shows every math step and lists the assumptions. No black boxes. */
window.AegisROI = (() => {
  "use strict";

  const ASSUMED_TRIAGE_HRS = 42; // analyst hours per incident (industry median)
  const AUTO_SHARE = 0.7; // share of triage Aegis automates (dedupe+correlate+playbook)

  function fmt(n) {
    return "$" + Math.round(n).toLocaleString("en-US");
  }
  function fmtHrs(n) {
    return (Math.round(n * 10) / 10).toLocaleString("en-US") + " hrs";
  }

  function num(id, fallback) {
    const v = parseFloat(document.getElementById(id).value);
    return isNaN(v) || v < 0 ? fallback : v;
  }

  function calc() {
    const incidents = num("roi-incidents", 1);
    const breachCost = num("roi-breach", 250000);
    const hourly = num("roi-hourly", 85);

    const expectedLoss = incidents * breachCost;
    const triageHrs = incidents * ASSUMED_TRIAGE_HRS;
    const triageCost = triageHrs * hourly;
    const autoHrs = triageHrs * AUTO_SHARE;
    const savings = autoHrs * hourly;
    const residualHrs = triageHrs - autoHrs;

    const steps = [
      ["Expected annual loss", incidents + " incident(s)/yr \u00d7 " + fmt(breachCost) + " avg breach cost", expectedLoss, true],
      ["Analyst hours burned on triage", incidents + " \u00d7 " + ASSUMED_TRIAGE_HRS + " hrs triage each", triageHrs, false],
      ["Triage cost", fmtHrs(triageHrs) + " \u00d7 " + fmt(hourly) + "/hr", triageCost, true],
      ["Aegis-automated triage", fmtHrs(triageHrs) + " \u00d7 " + Math.round(AUTO_SHARE * 100) + "% automated (dedupe, correlation, playbooks)", autoHrs, false],
      ["Net savings", fmtHrs(autoHrs) + " \u00d7 " + fmt(hourly) + "/hr", savings, true],
      ["Analyst time left for real work", fmtHrs(residualHrs) + " of human judgment per year \u2014 on cases, not alert triage", residualHrs, false],
    ];

    const out = document.getElementById("roi-output");
    out.innerHTML =
      '<div class="roi-steps">' +
      steps
        .map(
          (s) =>
            '<div class="roi-step">' +
            '<div class="roi-step-label">' + s[0] + "</div>" +
            '<div class="roi-step-math">' + s[1] + "</div>" +
            '<div class="roi-step-value' + (s[3] ? " roi-money" : "") + '">' +
            (s[3] ? fmt(s[2]) : fmtHrs(s[2])) +
            "</div></div>"
        )
        .join("") +
      "</div>" +
      '<p class="roi-note">Back-of-envelope. Dwell-time reduction (detection in minutes instead of days) ' +
      "is where the real money hides \u2014 it isn't in this math because it depends on your incident mix. " +
      "Adjust the inputs; the formulas don't change.</p>";

    const assumptions = document.getElementById("roi-assumptions");
    assumptions.innerHTML =
      "<li>" + ASSUMED_TRIAGE_HRS + " analyst-hours of triage per incident (industry median; yours may differ).</li>" +
      "<li>" + Math.round(AUTO_SHARE * 100) + "% of triage automated via dedupe, correlation, and playbooks \u2014 the rest still needs a human.</li>" +
      "<li>One incident per year is conservative; the average org sees more. Breach cost default ($250k) is SMB-skewed \u2014 the US average across all sizes is ~$4.45M.</li>" +
      "<li>Does not include Aegis operating cost (self-hosted: your infra) or the cost of incidents it prevents outright.</li>";
  }

  function init() {
    const btn = document.getElementById("roi-calc");
    if (!btn) return;
    ["roi-incidents", "roi-breach", "roi-hourly"].forEach((id) => {
      document.getElementById(id).addEventListener("input", calc);
    });
    btn.addEventListener("click", calc);
    calc();
  }

  return { init, calc };
})();
