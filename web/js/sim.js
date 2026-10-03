/* AegisSim — a JavaScript mirror of the Python Aegis pipeline
 * (aegis/models.py, aegis/pipeline/*). Same severity bands, same scoring
 * math, same correlation/dedupe semantics, so the demo behaves like the
 * real platform. Findings here are synthetic; engines run for real
 * server-side against live targets. */
window.AegisSim = (() => {
  "use strict";

  /* -- severity bands: identical to aegis.models.SCORE_BANDS -- */
  const SCORE_BANDS = [
    [90, "critical"],
    [70, "high"],
    [40, "medium"],
    [10, "low"],
    [0, "informational"],
  ];
  function severityForScore(score) {
    for (const [t, label] of SCORE_BANDS) {
      if (score >= t) return label;
    }
    return "informational";
  }

  /* -- asset criticality multipliers (mirrors pipeline/score.py) -- */
  const CRIT_MULT = { low: 0.9, normal: 1.0, high: 1.15, critical: 1.3 };

  /* -- event bus -- */
  const listeners = {};
  function on(evt, fn) {
    (listeners[evt] = listeners[evt] || []).push(fn);
    return () => {
      listeners[evt] = (listeners[evt] || []).filter((f) => f !== fn);
    };
  }
  function emit(evt, data) {
    (listeners[evt] || []).slice().forEach((fn) => {
      try {
        fn(data);
      } catch (e) {
        /* listener errors must not break the pipeline */
      }
    });
  }

  /* -- ids / fingerprints -- */
  let idc = 0;
  function newId(prefix) {
    idc += 1;
    return (
      prefix + "_" + idc.toString(36) + Date.now().toString(36).slice(-4)
    );
  }
  function djb2(str) {
    let h = 5381;
    for (let i = 0; i < str.length; i++) h = ((h << 5) + h + str.charCodeAt(i)) >>> 0;
    return h.toString(16);
  }
  function fingerprint(f) {
    const ent = Object.keys(f.entities || {})
      .sort()
      .map((k) => k + "=" + JSON.stringify(f.entities[k]))
      .join("|");
    return djb2(f.engine + "|" + f.title + "|" + ent);
  }

  const seen = new Set();
  const counters = {};
  const ENGINE_IDS = [
    "typo_watch", "dns_sentinel", "tls_watch", "port_watch",
    "auth_watch", "url_intel", "secret_sentry", "cve_watch",
    "cloud_posture", "phish_kit", "anomaly_mind", "canary_trip",
  ];
  ENGINE_IDS.forEach((id) => (counters[id] = 0));

  /* -- finding factory (mirrors aegis.models.Finding) -- */
  function makeFinding(engineId, spec) {
    const score = Math.max(0, Math.min(100, Number(spec.score) || 0));
    const f = {
      id: newId("fnd"),
      engine: engineId,
      title: spec.title || "Untitled finding",
      score: Math.round(score * 10) / 10,
      severity: severityForScore(score),
      entities: spec.entities || {},
      evidence: spec.evidence || {},
      recommendation: spec.recommendation || "",
      ts: new Date().toISOString(),
    };
    counters[engineId] = (counters[engineId] || 0) + 1;
    f.fingerprint = fingerprint(f);
    return f;
  }

  /* -- scoring stage (mirrors pipeline/score.py) -- */
  function adjustScore(finding, criticality) {
    const crit = CRIT_MULT[criticality] || CRIT_MULT.normal;
    const adjusted = Math.min(100, Math.round(finding.score * crit * 10) / 10);
    const factors = {
      base_score: finding.score,
      asset_criticality: criticality || "normal",
      multiplier: crit,
    };
    return Object.assign({}, finding, {
      adjustedScore: adjusted,
      adjustedSeverity: severityForScore(adjusted),
      scoreFactors: factors,
    });
  }

  /* -- dedupe stage (mirrors pipeline/dedupe.py) -- */
  function dedupe(findings) {
    const fresh = [];
    const dups = [];
    for (const f of findings) {
      if (seen.has(f.fingerprint)) dups.push(f);
      else {
        seen.add(f.fingerprint);
        fresh.push(f);
      }
    }
    return { fresh, dups };
  }

  /* -- correlation stage (mirrors pipeline/correlate.py) --
   * Groups findings that share an entity value into one case. Matches on
   * both "key:value" pairs and bare string values, because a campaign's
   * trail crosses entity keys (a domain seen as a lookalike in one
   * finding is the URL in another). */
  function entityValues(f) {
    const vals = [];
    const push = (k, v) => {
      if (v == null) return;
      const s = String(v);
      vals.push(k + ":" + s);
      if (typeof v === "string" && s.length > 2) vals.push(s); // bare value
    };
    for (const [k, v] of Object.entries(f.entities || {})) {
      if (Array.isArray(v)) v.forEach((x) => push(k, x));
      else push(k, v);
    }
    return vals;
  }
  function correlate(findings) {
    if (!findings.length) return [];
    const parent = findings.map((_, i) => i);
    const find = (i) => (parent[i] === i ? i : (parent[i] = find(parent[i])));
    const union = (a, b) => {
      parent[find(a)] = find(b);
    };
    const byEntity = {};
    findings.forEach((f, i) => {
      entityValues(f).forEach((ev) => {
        if (byEntity[ev] != null) union(i, byEntity[ev]);
        else byEntity[ev] = i;
      });
    });
    const groups = {};
    findings.forEach((f, i) => {
      const r = find(i);
      (groups[r] = groups[r] || []).push(f);
    });
    const cases = [];
    for (const g of Object.values(groups)) {
      if (g.length < 2) continue;
      const shared = Object.entries(
        g.flatMap(entityValues).reduce((m, ev) => {
          m[ev] = (m[ev] || 0) + 1;
          return m;
        }, {})
      )
        .filter(([, c]) => c > 1)
        .sort((a, b) => b[1] - a[1])[0];
      const score = Math.min(
        100,
        Math.round(Math.max(...g.map((f) => f.adjustedScore ?? f.score)) + 4)
      );
      const chain = g
        .slice()
        .sort((a, b) => a.ts.localeCompare(b.ts))
        .map((f) => shortTitle(f.title))
        .join(" \u2192 ");
      const narrative =
        g.length +
        " findings share " +
        (shared ? "'" + entityDisplay(shared[0]) + "'" : "an entity") +
        ": " +
        chain +
        ". This reads as one campaign, not " +
        g.length +
        " separate alerts.";
      cases.push({
        id: newId("case"),
        title: caseTitle(g),
        findings: g,
        severity: severityForScore(score),
        score,
        entities: g[0].entities,
        narrative,
        ts: new Date().toISOString(),
        status: "open",
      });
    }
    return cases;
  }
  function shortTitle(t) {
    return t.length > 64 ? t.slice(0, 61) + "\u2026" : t;
  }
  function entityDisplay(token) {
    /* "key:value" -> value; bare value -> itself */
    return token.includes(":") ? token.split(":").slice(1).join(":") : token;
  }
  function caseTitle(g) {
    const kinds = g.map((f) => f.engine);
    if (kinds.includes("phish_kit") || kinds.includes("typo_watch"))
      return "Brand impersonation campaign";
    if (kinds.includes("secret_sentry")) return "Credential exposure chain";
    if (kinds.includes("cve_watch")) return "Vulnerability exploitation chain";
    if (kinds.includes("cloud_posture")) return "Cloud compromise chain";
    if (kinds.includes("auth_watch")) return "Account takeover chain";
    return "Correlated attack chain";
  }

  /* -- the 12 engine detect functions: each is detect(input) -> finding|null.
   * Same input/output contract as Engine.scan(ctx) in Python. */
  const DETECT = {
    typo_watch(input) {
      const live = (input.lookalikes || []).filter((l) => l.live);
      if (!live.length) return null;
      const mx = live.filter((l) => l.mx).length;
      let score = 40 + 8 * live.length + (mx ? 25 : 0);
      return makeFinding("typo_watch", {
        title: live.length + " lookalike domain" + (live.length > 1 ? "s" : "") +
          " live for " + input.domain + (mx ? " (mail-capable)" : ""),
        score,
        entities: { domain: input.domain, lookalikes: live.map((l) => l.name) },
        evidence: { techniques: ["omission", "homoglyph", "bitsquat"], mx_count: mx },
        recommendation: "File registrar takedowns; add to mail-gateway blocklist.",
      });
    },
    dns_sentinel(input) {
      if (!input.drift) return null;
      return makeFinding("dns_sentinel", {
        title: "DNS drift on " + input.zone + ": " + input.rtype + " changed",
        score: input.rtype === "MX" ? 82 : 68,
        entities: { zone: input.zone, rtype: input.rtype },
        evidence: { before: input.before, after: input.after },
        recommendation: "Verify the change was authorized; revert if not.",
      });
    },
    tls_watch(input) {
      if (input.days_left >= 14) return null;
      return makeFinding("tls_watch", {
        title: "Certificate for " + input.host + " expires in " + input.days_left + "d",
        score: input.days_left < 3 ? 85 : 55,
        entities: { host: input.host },
        evidence: { days_left: input.days_left, weak_cipher: !!input.weak_cipher },
        recommendation: "Renew now; automate renewal to stop this recurring.",
      });
    },
    port_watch(input) {
      if (!input.new_ports || !input.new_ports.length) return null;
      const risky = input.new_ports.some((p) => [22, 3389, 3306, 5432, 6379, 27017].includes(p));
      return makeFinding("port_watch", {
        title: "New open port" + (input.new_ports.length > 1 ? "s" : "") +
          " on " + input.host + ": " + input.new_ports.join(", "),
        score: risky ? 88 : 52,
        entities: { host: input.host, ports: input.new_ports },
        evidence: { baseline: input.baseline_ports },
        recommendation: "Close or firewall the port if the change wasn't planned.",
      });
    },
    auth_watch(input) {
      if (input.pattern === "spray") {
        return makeFinding("auth_watch", {
          title: "Password spray: 1 password tried against " + input.users + " accounts",
          score: 86,
          entities: { src: input.src, users: input.users },
          evidence: { window_minutes: 10, failures: input.failures },
          recommendation: "Block the source; force resets on targeted accounts.",
        });
      }
      if (input.pattern === "mfa_fatigue") {
        return makeFinding("auth_watch", {
          title: "MFA fatigue: " + input.prompts + " push prompts to " + input.user,
          score: 89,
          entities: { user: input.user, src: input.src },
          evidence: { prompts: input.prompts, window_minutes: 3 },
          recommendation: "Switch to number-matching MFA; lock the account.",
        });
      }
      if (input.failures > 50) {
        return makeFinding("auth_watch", {
          title: "Brute force on " + input.user + " (" + input.failures + " failures)",
          score: 78,
          entities: { user: input.user, src: input.src },
          evidence: { failures: input.failures },
          recommendation: "Rate-limit the source IP; notify the user.",
        });
      }
      return null;
    },
    url_intel(input) {
      const hops = (input.chain || []).length;
      if (!hops) return null;
      let score = 20 + 12 * hops;
      if (input.domain_age_days < 30) score += 35;
      if (input.blocklisted) score += 25;
      return makeFinding("url_intel", {
        title: "Suspicious link resolves to " + input.final_host + " (" + hops + " hops)",
        score,
        entities: { url: input.url, final: input.final_host },
        evidence: { hops: input.chain, domain_age_days: input.domain_age_days },
        recommendation: "Block the domain; quarantine messages containing the link.",
      });
    },
    secret_sentry(input) {
      if (!input.leaks || !input.leaks.length) return null;
      const l = input.leaks[0];
      return makeFinding("secret_sentry", {
        title: "Possible " + l.kind + " leaked in " + l.repo,
        score: 94,
        entities: { repo: l.repo, kind: l.kind },
        evidence: { path: l.path, prefix: (l.value || "").slice(0, 8) + "\u2026" },
        recommendation: "Revoke the key immediately; purge from git history.",
      });
    },
    cve_watch(input) {
      if (!input.cve) return null;
      const score = Math.min(99, Math.round(30 + 60 * (input.epss || 0)));
      return makeFinding("cve_watch", {
        title: input.cve + " affects " + input.product + " " + input.version,
        score,
        entities: { cve: input.cve, product: input.product },
        evidence: { epss: input.epss, in_kev: !!input.in_kev, poc: !!input.poc_public },
        recommendation: input.poc_public ? "Patch now \u2014 exploit code is public." : "Schedule patching this cycle.",
      });
    },
    cloud_posture(input) {
      if (input.public_bucket) {
        return makeFinding("cloud_posture", {
          title: "Bucket " + input.public_bucket + " is publicly readable",
          score: 92,
          entities: { bucket: input.public_bucket },
          evidence: { policy: input.policy },
          recommendation: "Revoke the public policy; audit access logs.",
        });
      }
      if (input.new_admin_role) {
        return makeFinding("cloud_posture", {
          title: "New admin role created: " + input.new_admin_role,
          score: 88,
          entities: { role: input.new_admin_role },
          evidence: { creator: input.creator },
          recommendation: "Verify with the creator; remove if unauthorized.",
        });
      }
      if (input.open_sg) {
        return makeFinding("cloud_posture", {
          title: "Security group allows 0.0.0.0/0 on port " + input.open_sg,
          score: 78,
          entities: { port: input.open_sg },
          evidence: {},
          recommendation: "Restrict to known CIDRs.",
        });
      }
      return null;
    },
    phish_kit(input) {
      if (!input.kit) return null;
      return makeFinding("phish_kit", {
        title: "Phishing kit detected: " + input.kit + " at " + input.url,
        score: 91,
        entities: { url: input.url, kit: input.kit },
        evidence: { c2: input.c2, harvests: input.harvests },
        recommendation: "Takedown the domain; block the C2 hosts at the edge.",
      });
    },
    anomaly_mind(input) {
      if (input.impossible_travel) {
        return makeFinding("anomaly_mind", {
          title: "Impossible travel: " + input.user,
          score: 88,
          entities: { user: input.user },
          evidence: { route: input.route, minutes_apart: input.minutes },
          recommendation: "Lock the account; verify with the user out-of-band.",
        });
      }
      if ((input.z || 0) > 3) {
        return makeFinding("anomaly_mind", {
          title: "Unusual login pattern for " + input.user,
          score: 61,
          entities: { user: input.user },
          evidence: { z: input.z },
          recommendation: "Review; escalate if combined with other signals.",
        });
      }
      return null;
    },
    canary_trip(input) {
      if (!input.hit) return null;
      return makeFinding("canary_trip", {
        title: "Canary tripped: " + input.label,
        score: 96,
        entities: { canary: input.id, src: input.src },
        evidence: { hit_count: input.hits || 1 },
        recommendation: "Treat as compromise \u2014 no legitimate user touches this.",
      });
    },
  };

  function detect(engineId, input) {
    const fn = DETECT[engineId];
    return fn ? fn(input || {}) : null;
  }

  /* -- ambient mode: "internet background radiation".
   * Every tick there is a small chance of low-grade noise — the constant
   * scan chatter every public IP endures. Kept low-severity on purpose. */
  const AMBIENT_NOISE = [
    { title: "Port sweep from 45.155.204.18 (12 ports, no follow-through)", score: 12, engine: "port_watch", entities: { src: "45.155.204.18" } },
    { title: "DNS enumeration noise against mail.example.com", score: 18, engine: "dns_sentinel", entities: { zone: "mail.example.com" } },
    { title: "Single failed SSH login for 'root'", score: 8, engine: "auth_watch", entities: { user: "root" } },
    { title: "Scanner user-agent probing /wp-admin (404)", score: 15, engine: "url_intel", entities: { path: "/wp-admin" } },
    { title: "TLS handshake anomalies from datacenter ASN", score: 22, engine: "tls_watch", entities: { asn: "AS9009" } },
    { title: "SMB probe from 185.220.101.4 (Tor exit)", score: 26, engine: "port_watch", entities: { src: "185.220.101.4" } },
    { title: "Certificate transparency: unrelated lookalike seen", score: 14, engine: "typo_watch", entities: { domain: "examp1e-shop.com" } },
  ];
  function ambientTick(chance) {
    const p = chance == null ? 0.28 : chance;
    if (Math.random() > p) return null;
    const n = AMBIENT_NOISE[Math.floor(Math.random() * AMBIENT_NOISE.length)];
    const f = makeFinding(n.engine, {
      title: n.title,
      score: n.score,
      /* coarse time window: dedupe expires naturally, like the real
       * platform's time-bucketed fingerprints */
      entities: Object.assign({ _w: Math.floor(Date.now() / 60000) }, n.entities),
      evidence: { ambient: true },
    });
    const scored = adjustScore(f, "low");
    const { fresh } = dedupe([scored]);
    if (!fresh.length) return null;
    emit("finding", fresh[0]);
    return fresh[0];
  }

  function reset() {
    seen.clear();
    idc = 0;
    ENGINE_IDS.forEach((id) => (counters[id] = 0));
  }

  return {
    SCORE_BANDS,
    ENGINE_IDS,
    severityForScore,
    makeFinding,
    adjustScore,
    dedupe,
    correlate,
    fingerprint,
    detect,
    ambientTick,
    on,
    emit,
    reset,
    counters,
    CRIT_MULT,
  };
})();
