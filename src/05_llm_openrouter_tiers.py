"""
==========================================================
STEP 5c — PELAPORAN LLM: OPENROUTER 3 TIER
==========================================================

Menguji 3 tier model cloud untuk membandingkan pengaruh
ukuran model terhadap kualitas laporan forensik:

  TIER 1 — SMALL (~7–8B, setara lokal qwen2.5:1.5b ukuran besar):
    • qwen/qwen-2.5-7b-instruct        (~$0.07/1M token)
    • meta-llama/llama-3.1-8b-instruct (~$0.06/1M token)
    • mistralai/mistral-7b-instruct    (~$0.06/1M token)

  TIER 2 — MEDIUM (~70B, 10× lebih besar dari lokal):
    • qwen/qwen-2.5-72b-instruct       (~$0.35/1M token)
    • meta-llama/llama-3.3-70b-instruct(~$0.12/1M token)

  TIER 3 — LARGE (terbaik cloud):
    • anthropic/claude-3-haiku         (~$0.25/1M token)
    • google/gemini-flash-1.5          (~$0.075/1M token)

DEFAULT RUN : tier1 saja (3 model × 3 skenario = 9 run)
FULL RUN: semua tier (7 model × 3 skenario = 21 run)

CARA PAKAI:
  export OPENROUTER_API_KEY="sk-or-v1-xxxx..."

  # Tier 1 saja (hemat, cukup untuk perbandingan dasar):
  python3 05_llm_openrouter_tiers.py --tier 1

  # Tier 1 + 2 (direkomendasikan untuk tesis):
  python3 05_llm_openrouter_tiers.py --tier 1 2

  # Semua tier (maksimal, butuh lebih banyak kredit):
  python3 05_llm_openrouter_tiers.py --all

  # Model tertentu saja:
  python3 05_llm_openrouter_tiers.py --models qwen-72b llama-70b

  # Gabungkan ke CSV hasil lokal:
  python3 05_llm_openrouter_tiers.py --tier 1 2 --merge hasil_sparql_full/llm_evaluation_results.csv

REFERENSI:
  Studiawan et al. (2025) — 3 skenario, BLEU/ROUGE
  Michelet & Breitinger (2024) — LLM forensik, privasi cloud
  Chabot et al. (2015) — ORD2I ontology

CATATAN PRIVASI:
  Data forensic digest DIKIRIM ke server OpenRouter.
  Script ini HANYA untuk dataset publik Zenodo (MIT license).
  JANGAN gunakan untuk barang bukti nyata / kasus aktif.
"""

import os, sys, json, csv, re, time, argparse
import urllib.request, urllib.error

csv.field_size_limit(10 ** 7)

# ============================================================
# KONFIGURASI API
# ============================================================

OPENROUTER_API_KEY  = os.environ.get("OPENROUTER_API_KEY", "ISI_API_KEY_ANDA_DI_SINI")
OPENROUTER_URL      = "https://openrouter.ai/api/v1/chat/completions"
TIMEOUT             = 120

# ============================================================
# KATALOG MODEL — 3 TIER
# ============================================================

MODELS = {
    # ── Tier 1: Small (~7–8B) ─────────────────────────────
    "qwen-7b": {
        "id":    "qwen/qwen-2.5-7b-instruct",
        "tier":  1,
        "param": "7B",
        "price": "$0.07/1M",
        "note":  "Qwen2.5-7B — kesinambungan dengan model lokal qwen2.5:1.5b",
    },
    "llama-8b": {
        "id":    "meta-llama/llama-3.1-8b-instruct",
        "tier":  1,
        "param": "8B",
        "price": "$0.06/1M",
        "note":  "Llama 3.1 8B — Meta baseline, free tier tersedia",
    },
    "mistral-7b": {
        "id":    "mistralai/mistral-7b-instruct",
        "tier":  1,
        "param": "7B",
        "price": "$0.06/1M",
        "note":  "Mistral 7B v0.3 — European LLM baseline",
    },

    # ── Tier 2: Medium (~70B) ──────────────────────────────
    "qwen-72b": {
        "id":    "qwen/qwen-2.5-72b-instruct",
        "tier":  2,
        "param": "72B",
        "price": "$0.35/1M",
        "note":  "Qwen2.5-72B — isolasi efek ukuran vs qwen-7b",
    },
    "llama-70b": {
        "id":    "meta-llama/llama-3.3-70b-instruct",
        "tier":  2,
        "param": "70B",
        "price": "$0.12/1M",
        "note":  "Llama 3.3 70B — model terbaik Meta, lebih baru dari 3.1",
    },

    # ── Tier 3: Large (best-in-class) ─────────────────────
    "claude-haiku": {
        "id":    "anthropic/claude-3-haiku",
        "tier":  3,
        "param": "?",
        "price": "$0.25/1M",
        "note":  "Claude 3 Haiku — Anthropic, cepat dan akurat",
    },
    "gemini-flash": {
        "id":    "google/gemini-flash-1.5",
        "tier":  3,
        "param": "?",
        "price": "$0.075/1M",
        "note":  "Gemini 1.5 Flash — Google, 1M context window",
    },
}

OUTPUT_DIR = "hasil_sparql_full"
os.makedirs(OUTPUT_DIR, exist_ok=True)

# File input dari Step 3
Q2_FILE   = os.path.join(OUTPUT_DIR, "Q2_webpage_visits.csv")
Q3_FILE   = os.path.join(OUTPUT_DIR, "Q3_web_searches.csv")
Q4_FILE   = os.path.join(OUTPUT_DIR, "Q4_cookie_access.csv")
Q6_FILE   = os.path.join(OUTPUT_DIR, "Q6_app_execution.csv")
Q8_FILE   = os.path.join(OUTPUT_DIR, "Q8_registry_mods.csv")
Q9_FILE   = os.path.join(OUTPUT_DIR, "Q9_system_events.csv")
CORR_FILE = os.path.join(OUTPUT_DIR, "correlation_full_results.csv")
# Fallback jika pakai versi browser-only
if not os.path.exists(CORR_FILE):
    CORR_FILE = os.path.join("hasil_sparql", "correlation_results.csv")

# ============================================================
# GROUND TRUTH (sama persis dengan versi lokal)
# ============================================================

GROUND_TRUTH = """FORENSIC REPORT: Full Incident Reconstruction — Scenario 1
Dataset: Zenodo Scenario 1, Windows 11 Enterprise, Date: 2023-12-26

EXECUTIVE SUMMARY:
On 2023-12-26, a user on a Windows 11 Enterprise system initiated a 14-minute
session beginning at 00:34 UTC. The user launched Microsoft Edge, searched Bing
for Mozilla Firefox, downloaded and installed Firefox (00:37-00:44), then
immediately used Firefox to search for SQL injection attack techniques on Google
and visited a W3Schools SQL injection tutorial at 00:46:08 UTC.

FULL TIMELINE OF EVENTS:
1. [00:34:24] PREFETCH: MSEDGE.EXE executed (run_count=1) — Edge first launch
2. [00:35:11] BROWSER: microsoft.com/edge/welcome — Edge welcome page
3. [00:35:38] BROWSER: bing.com — User navigated to Bing search engine
4. [00:35:56] BROWSER: Bing search "mozilla firefox download"
5. [00:37:00] BROWSER: mozilla.org/en-US/firefox/download/thanks
6. [00:37:07] FILESTAT: Firefox Installer.exe downloaded from mozilla.org
7. [00:39:14] PREFETCH: FIREFOX INSTALLER.EXE executed (run_count=1)
8. [00:39:14] WINPCA: Firefox Installer.exe — compatibility assistance
9. [00:42:51-00:43:04] FILESTAT: Mozilla Firefox installation files written to
   C:\\Program Files\\Mozilla Firefox\\ (firefox.exe, xul.dll, nss3.dll, etc.)
10. [00:43:08] REGISTRY: Amcache entries for setup-stub.exe and maintenanceservice
11. [00:44:03] PREFETCH: FIREFOX.EXE executed (run_count=1) — first Firefox launch
12. [00:44:21] FILESTAT: FIREFOX.EXE accessed from installation directory
13. [00:44:45] BROWSER: mozilla.org/privacy/firefox — Firefox Privacy Notice
14. [00:44:47] BROWSER: mozilla.org/en-US/privacy/firefox [Firefox Privacy Notice]
15. [00:45:24] BROWSER: google.com — User navigated to Google
16. [00:45:45] BROWSER: Google search "how to perform sql injection attack"
17. [00:46:08] BROWSER: www.w3schools.com/sql/sql_injection.asp [SQL Injection]
18. [00:46:16] COOKIE: _ga @ w3schools.com — confirms active W3Schools visit
19. [00:48:14] BAM: firefox.exe — Background Activity Monitor last execution
20. [00:48:26] EVTLOG: UserLogon events — session ending

KEY FORENSIC FINDINGS:
1. ORD2I correlation score=1.000 confirms causal chain: SQL injection search
   directly preceded W3Schools tutorial access (delta-t = 23 seconds, CorrEK=1.0)
2. Firefox was freshly installed (prefetch run_count=1) only 2 minutes before
   the SQL injection search — deliberate preparation pattern
3. Firefox installation confirmed by 3 independent artifact sources:
   prefetch (FIREFOX INSTALLER.EXE), filestat (C:\\Program Files\\Mozilla Firefox\\),
   and registry/amcache (setup-stub.exe)
4. W3Schools cookies (_ga, _ga_9YNMTB56NB, _sharedID) independently confirm
   active page access — not just a URL record
5. No evidence of actual SQL injection execution found in artifacts
6. Edge/Bing activity (Phase 1) distinct from Firefox activity (Phase 3)
7. Total session: 14 minutes (00:34:22-00:48:28 UTC)

CONCLUSION:
The multi-source forensic evidence consistently demonstrates a deliberate and
focused session: the user specifically used Edge to find and install Firefox,
then within minutes used the fresh browser installation to search for and access
SQL injection attack information. The cross-artifact correlation between browser
history, prefetch execution records, registry changes, and cookie evidence
provides high confidence in the timeline reconstruction. This activity pattern
is consistent with reconnaissance or educational research into web attack
techniques and warrants further investigation.
"""


# ============================================================
# FORENSIC DIGEST (Full Scenario — 4 Fase)
# ============================================================

def build_digest():
    lines = []
    lines.append("=== FORENSIC EVIDENCE DIGEST — Full Scenario 1 ===")
    lines.append("Dataset : Zenodo Scenario 1 (Studiawan et al., 2025)")
    lines.append("OS      : Windows 11 Enterprise")
    lines.append("Date    : 2023-12-26, session 00:34–00:48 UTC (~14 minutes)")
    lines.append("Sources : Browser SQLite, NTFS filestat, Prefetch, Registry, Event Log")
    lines.append("Ontology: ORD2I (Chabot et al., 2015) — CKL + SKL + TKL")
    lines.append("")

    # ── Phase 1: Edge/Bing ───────────────────────────────────
    lines.append("--- [PHASE 1] EDGE/BING ACTIVITY — Firefox Download (00:34–00:41) ---")
    lines.append("  [00:34:24] PREFETCH  : MSEDGE.EXE executed (run_count=1)")
    lines.append("  [00:35:11] BROWSER   : microsoft.com/edge/welcome [Edge first launch]")
    lines.append("  [00:35:38] BROWSER   : bing.com [User navigated to Bing]")
    lines.append('  [00:35:56] BROWSER   : Bing search "mozilla firefox download"')
    lines.append("  [00:37:00] BROWSER   : mozilla.org/en-US/firefox/download/thanks")
    lines.append("  [00:37:07] FILESTAT  : Firefox Installer.exe downloaded from mozilla.org")
    lines.append("  [00:37:12] BROWSER   : login.live.com — Microsoft account detection")
    lines.append("")

    # ── Phase 2: Firefox Installation (Q6 key exes) ─────────
    lines.append("--- [PHASE 2] FIREFOX INSTALLATION (00:37–00:44) ---")
    if os.path.exists(Q6_FILE):
        seen = set()
        KEY_EXE = ["firefox installer","firefox.exe","setup-stub",
                   "maintenanceservice","default-browser-agent","helper.exe"]
        for r in sorted(csv.DictReader(open(Q6_FILE, encoding="utf-8")),
                        key=lambda x: x.get("timestamp","")):
            ts   = r.get("timestamp","")[:19].replace("T"," ")
            proc = r.get("process_name","").strip()
            fp   = r.get("file_path","").strip()
            et   = r.get("event_type","")
            # Pilih nama executable saja
            name = proc
            if not name:
                import os as _os
                bn = _os.path.basename(fp.replace("\\","/"))
                name = bn if "." in bn else ""
            if not name or name[:30] in seen: continue
            if not any(k in name.lower() for k in KEY_EXE): continue
            seen.add(name[:30])
            p = r.get("parser","")
            lines.append(f"  [{ts}] {et:<14}: {name[:55]}  [{p}]")
    # Registry
    if os.path.exists(Q8_FILE):
        seen_rk = set()
        for r in sorted(csv.DictReader(open(Q8_FILE, encoding="utf-8")),
                        key=lambda x: x.get("timestamp","")):
            ts = r.get("timestamp","")[:19].replace("T"," ")
            rk = r.get("registry_key","") or r.get("message","")[:80]
            if not any(k in rk.lower() for k in ["firefox","mozilla","amcache"]): continue
            if rk[:45] in seen_rk: continue
            seen_rk.add(rk[:45])
            lines.append(f"  [{ts}] REGISTRY     : {rk[:70]}")
            if len(seen_rk) >= 4: break
    lines.append("")

    # ── Phase 3: Firefox browser activity ───────────────────
    lines.append("--- [PHASE 3] FIREFOX BROWSER ACTIVITY (00:44–00:48) ---")
    if os.path.exists(Q2_FILE):
        seen_url = set()
        for r in sorted(csv.DictReader(open(Q2_FILE, encoding="utf-8")),
                        key=lambda x: x.get("timestamp","")):
            url = r.get("url","").strip()
            ts  = r.get("timestamp","")[:19].replace("T"," ")
            ttl = r.get("title","").strip()
            if not url or url in seen_url: continue
            if ts < "2023-12-26 00:44": continue
            seen_url.add(url)
            t = f" [{ttl}]" if ttl and ttl not in ("nan","") else ""
            lines.append(f"  [{ts}] BROWSER   : {url[:65]}{t}")
    if os.path.exists(Q3_FILE):
        seen_s = set()
        for r in csv.DictReader(open(Q3_FILE, encoding="utf-8")):
            url = r.get("url","").strip()
            ts  = r.get("timestamp","")[:19].replace("T"," ")
            m   = re.search(r'[?&](?:q|oq)=([^&]+)', url)
            q_str = m.group(1).replace("+"," ").replace("%20"," ") if m else ""
            if q_str and q_str not in seen_s:
                seen_s.add(q_str)
                lines.append(f'  [{ts}] SEARCH    : "{q_str}"')
    if os.path.exists(Q4_FILE):
        seen_ck = set(); cc = 0
        for r in csv.DictReader(open(Q4_FILE, encoding="utf-8")):
            ts  = r.get("timestamp","")[:19].replace("T"," ")
            nm  = r.get("cookie_name","").strip()
            dom = r.get("cookie_domain","").strip()
            if not nm:
                mx = re.search(r'(https?://[^\s]+)\s*\(([^)]+)\)', r.get("message",""))
                if mx: dom, nm = mx.group(1), mx.group(2)
            key = f"{nm[:20]}@{dom[:35]}"
            if key not in seen_ck:
                seen_ck.add(key)
                lines.append(f"  [{ts}] COOKIE    : {nm[:25]} @ {dom[:45]}")
                cc += 1
            if cc >= 8: break
    lines.append("")

    # ── Phase 4: System events ───────────────────────────────
    lines.append("--- [PHASE 4] SYSTEM EVENTS (00:48) ---")
    lines.append("  [00:48:14] BAM       : firefox.exe — last execution (Background Activity Monitor)")
    lines.append("  [00:48:26] EVTLOG    : UserLogon events — session ending indicators")
    lines.append("")

    # ── ORD2I Correlations ───────────────────────────────────
    lines.append("--- [ORD2I MULTI-ARTIFACT CORRELATIONS] ---")
    lines.append("  Formula: Corr(e1,e2) = (CorrT + CorrS + CorrO)/3 + CorrEK")
    if os.path.exists(CORR_FILE):
        seen_p = set(); shown = 0
        rows_c = sorted(csv.DictReader(open(CORR_FILE, encoding="utf-8")),
                        key=lambda x: float(x.get("score",0)), reverse=True)
        for r in rows_c:
            u1 = r.get("event1_url","") or r.get("event1_app","") or r.get("event1_path","")
            u2 = r.get("event2_url","") or r.get("event2_app","") or r.get("event2_path","")
            if u1==u2: continue
            t1  = r.get("event1_time","")[:19]
            t2  = r.get("event2_time","")[:19]
            sc  = float(r.get("score",0))
            ek  = r.get("CorrEK","?")
            key = (r.get("event1_type",""), u1[:35], r.get("event2_type",""), u2[:35])
            if key in seen_p: continue
            seen_p.add(key)
            lines.append(f"  score={sc:.3f} | CorrT={r.get('CorrT','?')} | "
                         f"CorrS={r.get('CorrS','?')} | CorrO={r.get('CorrO','?')} | "
                         f"CorrEK={ek}")
            lines.append(f"  {r.get('event1_type','')} → {r.get('event2_type','')}")
            lines.append(f"    [{t1}] {u1[:65]}")
            lines.append(f"    [{t2}] {u2[:65]}")
            shown += 1
            if shown >= 5: break
    lines.append("")

    # ── Key findings ringkasan ───────────────────────────────
    lines.append("--- KEY FORENSIC FINDINGS (for report generation) ---")
    lines.append("  1. Edge used to search and download Firefox (Phase 1: 00:34-00:41)")
    lines.append("  2. Firefox installed via 3 artifact sources: prefetch + filestat + registry")
    lines.append("     (FIREFOX INSTALLER.EXE run_count=1, setup-stub.exe amcache)")
    lines.append("  3. Firefox first run: FIREFOX.EXE prefetch 00:44:03, BAM 00:48:14")
    lines.append("  4. Within 2 minutes of Firefox launch: searched SQL injection attack techniques")
    lines.append("  5. W3Schools visited 23 seconds after SQL injection search (score=1.000)")
    lines.append("  6. W3Schools cookies (_ga, _sharedID) independently confirm active visit")
    lines.append("  7. No actual attack execution artifacts found — reconnaissance/learning pattern")
    lines.append("  8. Total session: 14 minutes (00:34:22–00:48:28 UTC), Windows 11 Enterprise")

    return "\n".join(lines)


# ============================================================
# PROMPTS — S1 / S2 / S3
# ============================================================

def prompt_s1(digest):
    return (
        "You are a professional digital forensic analyst. "
        "Write a COMPLETE forensic reconstruction of the ENTIRE incident "
        "based on ALL evidence sources provided below.\n"
        "The evidence covers 4 phases: Edge browser activity, Firefox installation, "
        "Firefox browsing activity, and session end events.\n"
        "Label each timeline entry with its artifact source "
        "(BROWSER / PREFETCH / FILESTAT / REGISTRY / COOKIE / EVTLOG).\n"
        "Do NOT invent facts. Use only the timestamps, URLs, and filenames from the evidence.\n\n"
        f"MULTI-SOURCE EVIDENCE:\n{digest}\n\n"
        "FORENSIC REPORT:\n"
        "EXECUTIVE SUMMARY: [1-2 sentences covering all 4 phases]\n"
        "FULL TIMELINE: [every significant event from 00:34 to 00:48, labeled by source]\n"
        "KEY FINDINGS: [suspicious patterns across all artifact types]\n"
        "CONCLUSION: [user intent assessment with confidence level]"
    )


def prompt_s2(digest):
    corr_ctx = (
        "ORD2I CROSS-ARTIFACT CORRELATION RESULTS:\n"
        "\n"
        "TOP CORRELATION — score=1.000 (CorrEK=1.0, CorrT=0.928, CorrS=1.0):\n"
        "  WebSearch → WebpageVisit [CAUSAL CHAIN CONFIRMED]\n"
        "  [00:45:45] SEARCH: 'how to perform sql injection attack' (Firefox SQLite)\n"
        "  [00:46:08] VISIT:  www.w3schools.com/sql/sql_injection.asp (Firefox SQLite)\n"
        "  Δt = 23 seconds — CorrEK rule: WebSearch directly followed by "
        "non-search-engine WebpageVisit = intentional causal chain\n"
        "\n"
        "CROSS-ARTIFACT CHAIN — score≈0.85 (CorrEK=0.9):\n"
        "  FileDownload → AppExecution [INSTALLATION CONFIRMED]\n"
        "  [00:37:07] Firefox Installer.exe (Edge chrome_cache / filestat)\n"
        "  [00:39:14] FIREFOX INSTALLER.EXE prefetch run_count=1\n"
        "  → Installer downloaded then immediately executed\n"
        "\n"
        "CROSS-ARTIFACT CHAIN — score≈0.80 (CorrEK=0.7):\n"
        "  AppLaunch → WebpageVisit [FIRST RUN CONFIRMED]\n"
        "  [00:44:03] FIREFOX.EXE prefetch first execution\n"
        "  [00:44:45] mozilla.org/privacy/firefox (Firefox SQLite)\n"
        "  → Browser launched then immediately displayed privacy notice\n"
        "\n"
        "ORD2I TKL: InvestigativeOp_FullScenario1 | Tool: log2timeline/Plaso "
        "| Confidence: 0.9 | Parsers: all Windows 11 artifact parsers\n"
    )
    return (
        "You are a professional digital forensic analyst. "
        "Write a COMPLETE forensic reconstruction using ORD2I multi-artifact "
        "correlation analysis. The evidence spans ALL Windows 11 artifact types.\n\n"
        f"MULTI-SOURCE EVIDENCE:\n{digest}\n\n"
        f"ORD2I CORRELATION ANALYSIS:\n{corr_ctx}\n"
        "FORENSIC REPORT:\n"
        "EXECUTIVE SUMMARY: [2-3 sentences covering all 4 phases and key correlations]\n"
        "FULL TIMELINE: [label each entry: BROWSER/PREFETCH/FILESTAT/REGISTRY/COOKIE/EVTLOG]\n"
        "KEY FINDINGS: [include ORD2I cross-artifact correlation scores and artifact sources]\n"
        "CONCLUSION: [user intent, confidence level, recommended next steps]"
    )


def prompt_s3(digest):
    example = (
        "=== FORMAT EXAMPLE — Full Incident Reconstruction ===\n"
        "FORENSIC REPORT — Full Incident Reconstruction\n\n"
        "EXECUTIVE SUMMARY:\n"
        "On [DATE], a user on [OS] conducted a [duration] session. "
        "The user [phase 1 summary]. Following this, [phase 2 summary]. "
        "The session concluded with [phase 3-4 summary].\n\n"
        "FULL TIMELINE:\n"
        "- [00:XX:XX] [SOURCE]   : [Event] — [significance]\n"
        "- [00:XX:XX] [SOURCE]   : [Event] — [significance]\n"
        "- [00:XX:XX] [SOURCE]   : [Event] — [significance]\n\n"
        "KEY FINDINGS:\n"
        "1. [Finding from browser evidence with timestamp]\n"
        "2. [Finding from execution/prefetch evidence with run_count]\n"
        "3. [Finding from registry evidence with key name]\n"
        "4. [ORD2I causal chain with correlation score]\n"
        "5. [Overall pattern assessment]\n\n"
        "CONCLUSION:\n"
        "[Assessment]. Confidence: [HIGH/MEDIUM/LOW]. "
        "Recommended action: [specific next step].\n"
        "=== END FORMAT ===\n\n"
        "INSTRUCTIONS: Fill the format above using ONLY the evidence below. "
        "Replace [SOURCE] with: BROWSER, PREFETCH, FILESTAT, REGISTRY, COOKIE, or EVTLOG. "
        "Use exact timestamps and filenames from the evidence. "
        "Cover all 4 phases: Edge download, Firefox install, Firefox browsing, session end.\n"
    )
    return (
        f"{example}"
        f"MULTI-SOURCE EVIDENCE:\n{digest}\n\n"
        "FORENSIC REPORT — Full Incident Reconstruction\n\n"
        "EXECUTIVE SUMMARY:\n"
        "On 2023-12-26, a user on Windows 11 Enterprise"
    )


# ============================================================
# OPENROUTER API CALL
# ============================================================

def call_openrouter(prompt, model_id, api_key, max_tokens=700):
    sys_msg = (
        "You are a professional digital forensic analyst with expertise in "
        "Windows artifact analysis, browser forensics, and ORD2I ontology. "
        "Write complete, structured forensic reports. "
        "Base your analysis ONLY on provided evidence. "
        "Do not hallucinate facts, timestamps, or file paths."
    )
    payload = json.dumps({
        "model":       model_id,
        "messages":    [
            {"role": "system", "content": sys_msg},
            {"role": "user",   "content": prompt},
        ],
        "temperature": 0.1,
        "max_tokens":  max_tokens,
        "top_p":       0.9,
    }).encode("utf-8")

    req = urllib.request.Request(
        OPENROUTER_URL, data=payload,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type":  "application/json",
            "HTTP-Referer":  "https://github.com/ord2i-forensic-thesis",
            "X-Title":       "ORD2I Full Scenario Pipeline",
        },
        method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            data    = json.loads(resp.read().decode("utf-8"))
            choices = data.get("choices", [])
            if not choices:
                err = data.get("error", {})
                return None, f"[ERROR] {err.get('message', 'No choices')}"
            content = choices[0].get("message", {}).get("content", "")
            usage   = data.get("usage", {})
            tokens  = (usage.get("prompt_tokens",0), usage.get("completion_tokens",0))
            return content, tokens

    except urllib.error.HTTPError as e:
        body = ""
        try: body = e.read().decode("utf-8")[:200]
        except: pass
        codes = {
            401: "Unauthorized — cek API key",
            402: "kredit habis — isi di openrouter.ai/credits",
            429: "rate limit — tunggu 60 detik",
            503: "model tidak tersedia saat ini",
        }
        return None, f"[ERROR] HTTP {e.code} {codes.get(e.code,'')}: {body}"
    except urllib.error.URLError as e:
        if "timed out" in str(e).lower():
            return None, f"[ERROR] Timeout {TIMEOUT}s"
        return None, f"[ERROR] {e}"


# ============================================================
# EVALUASI BLEU / ROUGE
# ============================================================

def evaluate(hypothesis, reference):
    if not hypothesis or str(hypothesis).startswith("[ERROR]"):
        return {"bleu":0.0,"rouge1":0.0,"rouge2":0.0,"rougeL":0.0,"method":"error"}
    try:
        import evaluate as ev
        b = ev.load("bleu").compute(
            predictions=[hypothesis], references=[[reference]])
        r = ev.load("rouge").compute(
            predictions=[hypothesis], references=[reference])
        return {
            "bleu":   round(b.get("bleu",   0), 4),
            "rouge1": round(r.get("rouge1", 0), 4),
            "rouge2": round(r.get("rouge2", 0), 4),
            "rougeL": round(r.get("rougeL", 0), 4),
            "method": "evaluate",
        }
    except ImportError:
        print("    [WARN] library 'evaluate' tidak ada — word-overlap fallback")
        hw = set(hypothesis.lower().split())
        rw = set(reference.lower().split())
        ov = len(hw & rw)
        pr = ov / len(hw) if hw else 0
        rc = ov / len(rw) if rw else 0
        f1 = 2*pr*rc/(pr+rc) if pr+rc>0 else 0
        return {"bleu":round(pr,4),"rouge1":round(f1,4),
                "rouge2":0.0,"rougeL":round(f1,4),"method":"word-overlap"}


# ============================================================
# RUNNER — 3 skenario untuk 1 model
# ============================================================

def run_model(model_key, api_key, digest, max_tokens=700):
    info = MODELS[model_key]
    print(f"\n  {'─'*60}")
    print(f"  MODEL  : {model_key}  ({info['param']}, {info['price']})")
    print(f"  ID     : {info['id']}")
    print(f"  Tier   : {info['tier']}  |  {info['note']}")
    print(f"  {'─'*60}")

    scenarios = [
        ("S1_without_knowledge", "S1 — Tanpa knowledge", prompt_s1(digest)),
        ("S2_with_knowledge",    "S2 — Dengan ORD2I",   prompt_s2(digest)),
        ("S3_few_shot",          "S3 — Few-shot",       prompt_s3(digest)),
    ]

    results = []
    prefix  = re.sub(r'[^a-z0-9]', '_', model_key.lower())[:20]

    for sc_key, sc_desc, sc_prompt in scenarios:
        print(f"\n  [{sc_key}]  prompt={len(sc_prompt)} char")
        t0              = time.time()
        content, tokens = call_openrouter(sc_prompt, info["id"], api_key, max_tokens)
        secs            = round(time.time() - t0, 1)

        is_err = content is None or str(content).startswith("[ERROR]")

        if is_err:
            print(f"  ❌ GAGAL: {tokens}")
            output = str(tokens)
        else:
            output = content
            tok_str = f"  [tokens] prompt={tokens[0]} completion={tokens[1]}" \
                      if isinstance(tokens, tuple) else ""
            print(f"  ✅ {len(output)} char dalam {secs}s{tok_str}")
            print("  " + output[:300].replace("\n", "\n  "))
            print("  ...")

        scores = evaluate(output, GROUND_TRUTH)
        mean_s = round(sum(scores[k] for k in ["bleu","rouge1","rouge2","rougeL"])/4, 4)
        method = scores.pop("method", "?")

        print(f"\n  BLEU={scores['bleu']:.4f} R1={scores['rouge1']:.4f} "
              f"R2={scores['rouge2']:.4f} RL={scores['rougeL']:.4f} "
              f"Mean={mean_s:.4f}  [{method}]")

        # Simpan laporan
        fname = os.path.join(OUTPUT_DIR,
                             f"openrouter_{prefix}_{sc_key}_report.txt")
        with open(fname, "w", encoding="utf-8") as f:
            f.write(f"=== {sc_desc} ===\n")
            f.write(f"Provider   : OpenRouter\n")
            f.write(f"Model      : {info['id']}\n")
            f.write(f"Model key  : {model_key}\n")
            f.write(f"Tier       : {info['tier']}\n")
            f.write(f"Param      : {info['param']}\n")
            f.write(f"Waktu      : {secs}s\n")
            f.write(f"Tokens     : {tokens}\n")
            f.write(f"Metode eval: {method}\n")
            f.write(f"BLEU       : {scores['bleu']:.4f}\n")
            f.write(f"ROUGE-1    : {scores['rouge1']:.4f}\n")
            f.write(f"ROUGE-2    : {scores['rouge2']:.4f}\n")
            f.write(f"ROUGE-L    : {scores['rougeL']:.4f}\n")
            f.write(f"Mean       : {mean_s:.4f}\n")
            f.write("="*60+"\n\n")
            f.write(output)
        print(f"  Disimpan: {fname}")

        results.append({
            "provider":    "OpenRouter",
            "model":       info["id"],
            "model_key":   model_key,
            "tier":        info["tier"],
            "param":       info["param"],
            "scenario":    sc_key,
            "bleu":        scores["bleu"],
            "rouge1":      scores["rouge1"],
            "rouge2":      scores["rouge2"],
            "rougeL":      scores["rougeL"],
            "mean":        mean_s,
            "output_len":  len(output),
            "time_s":      secs,
            "tokens":      str(tokens),
            "success":     not is_err,
            "eval_method": method,
        })

        time.sleep(2)   # hindari rate limit

    return results


# ============================================================
# TABEL HASIL
# ============================================================

def print_table(all_results):
    print(f"\n{'='*90}")
    print("TABEL EVALUASI — OpenRouter Multi-Tier")
    print(f"{'='*90}")
    print(f"{'Model':<20} {'Tier':>5} {'Param':>5} "
          f"{'Sc':>3} {'BLEU':>7} {'R-1':>7} {'R-2':>7} {'R-L':>7} "
          f"{'Mean':>7} {'t':>5}")
    print(f"{'─'*90}")

    prev = ""
    for r in all_results:
        mk = r.get("model_key","")[:18]
        if mk != prev and prev:
            print(f"{'─'*90}")
        prev = mk
        sc   = {"S1_without_knowledge":"S1","S2_with_knowledge":"S2",
                "S3_few_shot":"S3"}.get(r["scenario"], r["scenario"][:3])
        flag = "" if r["success"] else " ✗"
        print(f"  {mk:<20} {r['tier']:>5} {r['param']:>5} "
              f"{sc:>3} {r['bleu']:>7.4f} {r['rouge1']:>7.4f} "
              f"{r['rouge2']:>7.4f} {r['rougeL']:>7.4f} "
              f"{r['mean']:>7.4f} {r['time_s']:>4.0f}s{flag}")

    print(f"{'='*90}")

    # Ringkasan per model
    print("\nRINGKASAN PER MODEL:")
    keys_done = []
    for r in all_results:
        mk = r.get("model_key","")
        if mk not in keys_done: keys_done.append(mk)
    for mk in keys_done:
        sub     = [r for r in all_results if r.get("model_key")==mk and r["success"]]
        if not sub: continue
        avg     = round(sum(r["mean"] for r in sub)/len(sub), 4)
        best    = max(sub, key=lambda x: x["mean"])
        best_sc = {"S1_without_knowledge":"S1","S2_with_knowledge":"S2",
                   "S3_few_shot":"S3"}.get(best["scenario"],"?")
        info    = MODELS.get(mk,{})
        print(f"  {mk:<20} Tier={info.get('tier','?')} {info.get('param','?'):>5}  "
              f"avg Mean={avg:.4f}  best={best_sc} ({best['mean']:.4f})")

    # Perbandingan antar tier
    tier_avgs = {}
    for t in [1,2,3]:
        sub = [r for r in all_results if r.get("tier")==t and r["success"]]
        if sub:
            tier_avgs[t] = round(sum(r["mean"] for r in sub)/len(sub), 4)
    if len(tier_avgs) > 1:
        print("\nAVERAGE MEAN PER TIER:")
        for t in sorted(tier_avgs):
            label = {1:"~7-8B (Small)",2:"~70B (Medium)",3:"Best-in-class (Large)"}[t]
            print(f"  Tier {t} {label:<25}: {tier_avgs[t]:.4f}")


# ============================================================
# MAIN
# ============================================================

def main():
    ap = argparse.ArgumentParser(
        description="Step 5c — LLM Report: OpenRouter Multi-Tier")
    ap.add_argument("--tier", nargs="+", type=int, default=[1],
        choices=[1,2,3],
        help="Tier yang dijalankan (default: 1). Contoh: --tier 1 2")
    ap.add_argument("--all", action="store_true",
        help="Jalankan semua tier (1+2+3)")
    ap.add_argument("--models", nargs="+", default=None,
        choices=list(MODELS.keys()),
        help=f"Model spesifik. Pilihan: {list(MODELS.keys())}")
    ap.add_argument("--max-tokens", type=int, default=700,
        help="Max tokens output per call (default: 700)")
    ap.add_argument("--merge", type=str, default=None, metavar="CSV",
        help="Gabungkan hasil ke CSV yang ada. "
             "Contoh: --merge hasil_sparql_full/llm_evaluation_results.csv")
    args = ap.parse_args()

    # Cek API key
    api_key = OPENROUTER_API_KEY
    if not api_key or api_key == "ISI_API_KEY_ANDA_DI_SINI" or len(api_key) < 20:
        print("❌ API key belum diset!")
        print()
        print("   export OPENROUTER_API_KEY=\"sk-or-v1-xxxx...\"")
        print("   kemudian jalankan lagi.")
        print()
        print("   Pantau kredit: https://openrouter.ai/credits")
        sys.exit(1)

    # Tentukan model yang akan dijalankan
    if args.models:
        target_keys = args.models
    elif args.all:
        target_keys = list(MODELS.keys())
    else:
        tiers = set(args.tier)
        target_keys = [k for k,v in MODELS.items() if v["tier"] in tiers]

    # Hitung estimasi biaya (kasar)
    n_calls = len(target_keys) * 3
    print("=" * 65)
    print("STEP 5c — Pelaporan LLM Cloud: OpenRouter Multi-Tier")
    print("=" * 65)
    print(f"  API key   : ...{api_key[-6:]}")
    print(f"  Model run : {target_keys}")
    print(f"  Skenario  : S1 (tanpa knowledge), S2 (ORD2I), S3 (few-shot)")
    print(f"  Max token : {args.max_tokens}")
    print(f"  Total call: {n_calls} API calls")
    print(f"  Output dir: {OUTPUT_DIR}/")
    print()
    print("  ⚠  PRIVASI: digest dikirim ke OpenRouter.")
    print("     Hanya gunakan untuk dataset PUBLIK (Zenodo MIT license).")
    print()

    # Build digest
    print("[1] Membangun forensic digest...")
    digest = build_digest()
    print(f"    ✅ {len(digest)} karakter, {len(digest.splitlines())} baris")
    print(f"    Cakupan: 4 fase × semua artefak (browser+prefetch+registry+evtlog)")

    # Jalankan per model
    all_results = []
    print(f"\n[2] Menjalankan {len(target_keys)} model ({n_calls} total API call)...")

    for mk in target_keys:
        results = run_model(mk, api_key, digest, args.max_tokens)
        all_results.extend(results)

    if not all_results:
        print("\n❌ Tidak ada hasil.")
        return

    # Tampilkan tabel
    print_table(all_results)

    # Simpan CSV
    out_csv = os.path.join(OUTPUT_DIR, "llm_evaluation_openrouter_tiers.csv")
    with open(out_csv, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=all_results[0].keys())
        w.writeheader()
        w.writerows(all_results)
    print(f"\n✅ CSV disimpan: {out_csv}")

    # Merge jika diminta
    if args.merge:
        existing = []
        if os.path.exists(args.merge):
            existing = list(csv.DictReader(open(args.merge, encoding="utf-8")))
            print(f"  [merge] {len(existing)} baris lama + {len(all_results)} baru")
        combined  = existing + all_results
        all_keys  = list(dict.fromkeys(k for r in combined for k in r.keys()))
        with open(args.merge, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=all_keys, extrasaction="ignore")
            w.writeheader()
            w.writerows(combined)
        print(f"✅ Merged ke: {args.merge} ({len(combined)} baris total)")

    n_ok = sum(1 for r in all_results if r["success"])
    print(f"✅ {n_ok}/{len(all_results)} skenario berhasil")
    print()
    print("Contoh run berikutnya:")
    print(f"  Tier 2 saja  : python3 05_llm_openrouter_tiers.py --tier 2")
    print(f"  Semua tier   : python3 05_llm_openrouter_tiers.py --all")
    print(f"  Merge lokal  : python3 05_llm_openrouter_tiers.py --tier 1 "
          f"--merge {OUTPUT_DIR}/llm_evaluation_results.csv")


if __name__ == "__main__":
    main()
