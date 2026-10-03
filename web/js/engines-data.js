/* AEGIS_ENGINES — the 12 detection engines.
 * Snippets mirror the real implementations at aegis/engines/<id>.py
 * (same ScanContext contract, same self.finding() helper). */
window.AEGIS_ENGINES = [
  {
    id: "typo_watch",
    name: "typo_watch",
    tagline: "Lookalike domain radar. Catches the fakes before your customers do.",
    plainEnglish:
      "Attackers register domains that look almost like yours \u2014 paypa1.com instead of paypal.com \u2014 and use them to steal logins. " +
      "typo_watch generates every plausible misspelling of your domains, checks which ones are actually registered and live, " +
      "and scores them by how dangerous they look. A live mail server on a lookalike is a phishing campaign waiting to happen.",
    technique:
      "Generative lookalike variants (omission, insertion, transposition, homoglyph, bitsquat and 7 more) scored against live DNS, MX, and certificate-transparency logs.",
    repoPath: "aegis/engines/typo_watch.py",
    snippet: [
      "def scan(self, ctx: ScanContext) -> list[Finding]:",
      "    out = []",
      '    for domain in ctx.targets.get("domains", []):',
      "        for variant in generate_lookalikes(domain):  # 12 techniques",
      '            if not ctx.dns_resolve(variant, "A"):',
      "                continue                      # not registered: skip",
      "            score = 40.0",
      '            if ctx.dns_resolve(variant, "MX"):',
      "                score += 30.0   # can send mail as you",
      "            if ct_log_has_cert(variant, ctx):",
      "                score += 15.0   # has TLS: looks legitimate",
      "            out.append(self.finding(",
      '                f"Lookalike domain is live: {variant}", score,',
      '                entities={"domain": variant, "impersonates": domain}))',
      "    return out",
    ].join("\n"),
  },
  {
    id: "dns_sentinel",
    name: "dns_sentinel",
    tagline: "DNS drift detector. Notices when your DNS quietly changes.",
    plainEnglish:
      "Your DNS records are the internet's signposts \u2014 change one and your traffic goes somewhere else. " +
      "dns_sentinel keeps a baseline of what your DNS should look like and shouts when something drifts. " +
      "A new MX record you didn't add means someone may be intercepting your email.",
    technique:
      "Baselined A/AAAA/MX/NS/TXT records with drift scoring; flags unexpected record changes, new subdomains, and hijack-shaped edits.",
    repoPath: "aegis/engines/dns_sentinel.py",
    snippet: [
      "def scan(self, ctx: ScanContext) -> list[Finding]:",
      "    out, baseline = [], load_baseline(ctx)   # last known-good DNS",
      '    for zone in ctx.targets.get("zones", []):',
      '        live = {r: ctx.dns_resolve(zone, r) for r in ("A","MX","NS","TXT")}',
      "        for rtype, records in live.items():",
      "            if records != baseline.get(zone, {}).get(rtype):",
      "                out.append(self.finding(",
      '                    f"DNS drift on {zone}: {rtype} changed", 72.0,',
      '                    entities={"zone": zone, "rtype": rtype},',
      '                    evidence={"before": baseline.get(zone, {}).get(rtype),',
      '                              "after": records}))',
      "    return out",
    ].join("\n"),
  },
  {
    id: "tls_watch",
    name: "tls_watch",
    tagline: "Certificate watchdog. Expiry and misconfig, before they bite.",
    plainEnglish:
      "Expired certificates take sites offline and erode trust; misconfigured ones invite interception. " +
      "tls_watch tracks every certificate you own, counts down to expiry, and grades the TLS configuration " +
      "the way an attacker would \u2014 weak ciphers, broken chains, all of it.",
    technique:
      "Certificate-transparency log and handshake inspection; expiry countdown with weak-cipher and chain-validation scoring.",
    repoPath: "aegis/engines/tls_watch.py",
    snippet: [
      "def scan(self, ctx: ScanContext) -> list[Finding]:",
      "    out = []",
      '    for host in ctx.targets.get("hosts", []):',
      "        cert = ctx.tls_inspect(host)       # handshake + CT log",
      "        days = (cert.not_after - ctx.now()).days",
      "        if days < 14:",
      "            out.append(self.finding(",
      '                f"Certificate for {host} expires in {days}d",',
      "                85.0 if days < 3 else 55.0,",
      '                entities={"host": host},',
      '                evidence={"not_after": cert.not_after.isoformat(),',
      '                          "weak_cipher": cert.weak_cipher}))',
      "    return out",
    ].join("\n"),
  },
  {
    id: "port_watch",
    name: "port_watch",
    tagline: "Attack-surface monitor. Knows every door you left open.",
    plainEnglish:
      "Every open port is a door. port_watch keeps a list of the doors you meant to leave open and flags new ones. " +
      "A database port suddenly reachable from the internet is the kind of thing breaches are made of \u2014 " +
      "this engine notices the hour it happens, not the quarter it gets audited.",
    technique:
      "Periodic port sweep diffed against a known-good baseline; new open ports scored by service risk.",
    repoPath: "aegis/engines/port_watch.py",
    snippet: [
      "def scan(self, ctx: ScanContext) -> list[Finding]:",
      "    out, baseline = [], load_baseline(ctx)  # known-good open ports",
      '    for host in ctx.targets.get("hosts", []):',
      "        open_now = set(ctx.port_scan(host))  # hook: real or fixture",
      "        for port in sorted(open_now - baseline.get(host, set())):",
      "            out.append(self.finding(",
      '                f"New open port on {host}: {port}/{service_name(port)}",',
      "                88.0 if port in RISKY else 52.0,",
      '                entities={"host": host, "port": port}))',
      "    return out",
    ].join("\n"),
  },
  {
    id: "auth_watch",
    name: "auth_watch",
    tagline: "Login attack detector. Reads your auth logs like a bouncer.",
    plainEnglish:
      "Most break-ins start with guessing passwords. auth_watch tails your login logs and recognizes the shapes of attacks: " +
      "one account tried a thousand times, one password tried against a thousand accounts, or a user bombarded " +
      "with MFA prompts until they tap approve just to make it stop.",
    technique:
      "Sliding-window analysis of auth logs; brute-force, password-spray, and MFA-fatigue pattern matching.",
    repoPath: "aegis/engines/auth_watch.py",
    snippet: [
      "def scan(self, ctx: ScanContext) -> list[Finding]:",
      "    out = []",
      "    for user, fails in windowed_failures(ctx, minutes=10).items():",
      '        if fails["distinct_sources"] == 1 and fails["count"] > 50:',
      '            out.append(self.finding(f"Brute force on {user}", 78.0,',
      '                entities={"user": user, "src": fails["top_source"]}))',
      '    spray = password_spray_shape(ctx)       # 1 password x many users',
      "    if spray:",
      '        out.append(self.finding("Password spray in progress", 86.0,',
      '            entities={"users": spray["users"], "src": spray["src"]}))',
      "    return out",
    ].join("\n"),
  },
  {
    id: "url_intel",
    name: "url_intel",
    tagline: "Link unwrapper. Sees where a link really goes.",
    plainEnglish:
      "Phishing lives behind shortened links and redirects. url_intel follows a link all the way to its final destination, " +
      "checks how old the domain is and how many hops it took to get there, and scores whether it smells like a trap. " +
      "A six-hour-old domain behind three redirects is not a newsletter.",
    technique:
      "Recursive unshortening, domain-age and redirect-chain scoring, blocklist and sandbox verdicts.",
    repoPath: "aegis/engines/url_intel.py",
    snippet: [
      "def scan(self, ctx: ScanContext) -> list[Finding]:",
      "    out = []",
      '    for url in ctx.targets.get("urls", []):',
      "        chain = follow_redirects(url, ctx)   # unshorten recursively",
      "        final = chain[-1]",
      "        score = 20.0 + 12.0 * len(chain)",
      "        if domain_age(final, ctx) < 30:      # days",
      "            score += 35.0                    # newborn domains are cheap",
      "        if final.host in blocklists(ctx):",
      "            score += 25.0",
      '        out.append(self.finding(f"Suspicious link -> {final.host}",',
      '            score, entities={"url": url, "final": str(final)},',
      '            evidence={"hops": [str(u) for u in chain]}))',
      "    return out",
    ].join("\n"),
  },
  {
    id: "secret_sentry",
    name: "secret_sentry",
    tagline: "Leaked-secret scanner. Finds your keys before strangers use them.",
    plainEnglish:
      "API keys end up in public code more often than anyone admits, and bots harvest them within minutes of the push. " +
      "secret_sentry scans for key patterns, uses entropy math to tell real secrets from random strings, " +
      "and tells you exactly which key leaked and where \u2014 so you can revoke it before it's abused.",
    technique:
      "High-signal regex plus Shannon-entropy scoring across repos, gists, and paste sites; canary correlation.",
    repoPath: "aegis/engines/secret_sentry.py",
    snippet: [
      "def scan(self, ctx: ScanContext) -> list[Finding]:",
      "    out = []",
      '    for repo in ctx.targets.get("repos", []):',
      "        for path, blob in iter_blobs(repo, ctx):",
      "            for kind, value in find_candidates(blob):  # regex+entropy",
      "                if entropy(value) < 4.2:",
      "                    continue        # random-looking, not a secret",
      "                out.append(self.finding(",
      '                    f"Possible {kind} leaked in {repo}:{path}", 92.0,',
      '                    entities={"repo": repo, "path": path, "kind": kind},',
      '                    evidence={"prefix": value[:8] + "\u2026"}))',
      "    return out",
    ].join("\n"),
  },
  {
    id: "cve_watch",
    name: "cve_watch",
    tagline: "Vulnerability radar. Matches new CVEs against what you actually run.",
    plainEnglish:
      "Thousands of vulnerabilities are published every year; only a handful affect software you actually run. " +
      "cve_watch reads the firehose, matches it against your inventory, and prioritizes by whether attackers " +
      "are really exploiting it \u2014 not just how scary the description sounds.",
    technique:
      "CVE feed ingestion joined to your asset inventory; EPSS-weighted exploitability scoring.",
    repoPath: "aegis/engines/cve_watch.py",
    snippet: [
      "def scan(self, ctx: ScanContext) -> list[Finding]:",
      '    out, inventory = [], ctx.targets.get("inventory", {})',
      "    for cve in ctx.cve_feed(since_days=7):   # hook: NVD or fixture",
      "        for product, version in inventory.items():",
      "            if not affects(cve, product, version):",
      "                continue",
      "            score = 30.0 + 60.0 * cve.epss   # exploited-in-wild weight",
      "            out.append(self.finding(",
      '                f"{cve.id} affects {product} {version}", score,',
      '                entities={"cve": cve.id, "product": product},',
      '                evidence={"epss": cve.epss, "kev": cve.in_kev}))',
      "    return out",
    ].join("\n"),
  },
  {
    id: "cloud_posture",
    name: "cloud_posture",
    tagline: "Cloud drift guard. Catches the config change that opens everything.",
    plainEnglish:
      "Cloud breaches are rarely fancy hacks \u2014 they're a storage bucket flipped to public, or an over-permissive role " +
      "someone created at 5pm on a Friday. cloud_posture snapshots your cloud configuration, diffs it against what you declared, " +
      "and scores drift by how exposed it leaves you.",
    technique:
      "Cloud API snapshots diffed against policy-as-code; public-exposure and privilege-escalation path scoring.",
    repoPath: "aegis/engines/cloud_posture.py",
    snippet: [
      "def scan(self, ctx: ScanContext) -> list[Finding]:",
      "    out = []",
      "    snap = ctx.cloud_snapshot()              # buckets, SGs, IAM",
      '    for bucket in snap["buckets"]:',
      '        if bucket["public"] and not declared_public(bucket, ctx):',
      "            out.append(self.finding(",
      '                f"Bucket {bucket[\'name\']} is publicly readable", 92.0,',
      '                entities={"bucket": bucket["name"]},',
      '                evidence={"policy": bucket["policy_summary"]}))',
      '    for role in snap["iam_new_admins"]:',
      '        out.append(self.finding(f"New admin role: {role}", 88.0,',
      '            entities={"role": role}))',
      "    return out",
    ].join("\n"),
  },
  {
    id: "phish_kit",
    name: "phish_kit",
    tagline: "Phishing-kit fingerprinting. Recognizes the criminal's toolkit.",
    plainEnglish:
      "Phishers reuse off-the-shelf kits, and kits have fingerprints \u2014 distinctive page structure, scripts, and callbacks " +
      "to the attacker's server. phish_kit compares suspicious pages against a library of known kits and tells you " +
      "which criminal toolset you're looking at, and where it phones home.",
    technique:
      "DOM/JS structural fingerprinting against a kit signature library; command-and-control callback detection.",
    repoPath: "aegis/engines/phish_kit.py",
    snippet: [
      "def scan(self, ctx: ScanContext) -> list[Finding]:",
      "    out = []",
      '    for url in ctx.targets.get("urls", []):',
      "        page = ctx.http_get(url)",
      "        kit = match_kit_signature(page.dom, page.scripts)  # prints",
      "        if not kit:",
      "            continue",
      "        out.append(self.finding(",
      '            f"Phishing kit detected: {kit.family} at {url}", 91.0,',
      '            entities={"url": url, "kit": kit.family},',
      '            evidence={"c2": kit.callback_hosts,',
      '                      "harvests": kit.harvest_fields}))',
      "    return out",
    ].join("\n"),
  },
  {
    id: "anomaly_mind",
    name: "anomaly_mind",
    tagline: "Behavioral anomaly engine. Notices when \u2018you\u2019 aren't you.",
    plainEnglish:
      "You log in from the same place at the same hours every day; at 3am from another continent is not you. " +
      "anomaly_mind learns the normal rhythm of every user and system \u2014 login hours, volumes, locations \u2014 " +
      "then flags deviations with the math to back it up.",
    technique:
      "Per-entity baselines (login hours, volumes, geolocation); z-score and impossible-travel detection.",
    repoPath: "aegis/engines/anomaly_mind.py",
    snippet: [
      "def scan(self, ctx: ScanContext) -> list[Finding]:",
      "    out = []",
      '    for user, events in ctx.targets.get("logins", {}).items():',
      "        base = load_baseline(ctx, user)      # hours, geo, volume",
      "        for e in events:",
      "            if impossible_travel(e, base):",
      "                out.append(self.finding(",
      '                    f"Impossible travel: {user}", 88.0,',
      '                    entities={"user": user},',
      '                    evidence={"route": f"{e.geo_from}->{e.geo_to}",',
      '                              "minutes": e.delta_minutes}))',
      "            elif zscore(e.hour, base.hours) > 3.0:",
      '                out.append(self.finding(f"Unusual hour: {user}", 61.0,',
      '                    entities={"user": user}))',
      "    return out",
    ].join("\n"),
  },
  {
    id: "canary_trip",
    name: "canary_trip",
    tagline: "Deception tripwires. Fake valuables that scream when touched.",
    plainEnglish:
      "A canary token is a fake API key or document that no legitimate user should ever touch \u2014 it's bait. " +
      "canary_trip plants them across your systems: in code repos, on file shares, in cloud accounts. " +
      "When one fires, there's no ambiguity to triage \u2014 someone is somewhere they shouldn't be.",
    technique:
      "Planted canary tokens (AWS keys, documents, credentials, URLs); any touch is a high-confidence compromise signal.",
    repoPath: "aegis/engines/canary_trip.py",
    snippet: [
      "def scan(self, ctx: ScanContext) -> list[Finding]:",
      "    out = []",
      '    for token in ctx.targets.get("canaries", []):',
      "        hits = ctx.canary_hits(token.id)     # token service pings us",
      "        if not hits:",
      "            continue",
      "        out.append(self.finding(",
      '            f"Canary tripped: {token.label}", 96.0,  # no legit reason',
      '            entities={"canary": token.id, "src": hits[0].ip},',
      '            evidence={"hit_count": len(hits),',
      '                      "first_seen": hits[0].ts}))',
      "    return out",
    ].join("\n"),
  },
];
