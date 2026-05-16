"""
==========================================================
STEP 5 — PELAPORAN LLM: 3 MODEL LOKAL + OPENROUTER (OPSIONAL)
==========================================================

MODEL YANG DIUJI:
  Lokal (Ollama):
    1. tinyllama:1.1b   — ~638 MB, paling ringan
    2. qwen2.5:0.5b     — ~400 MB, tercepat
    3. qwen2.5:1.5b     — ~1 GB, kualitas terbaik lokal

  Cloud (OpenRouter, opsional):
    4. qwen/qwen-2.5-7b-instruct — pembanding cloud

CARA PAKAI:
  # Jalankan 3 model lokal (default):
  python3 05_llm_report_multimodel.py

  # Jalankan model tertentu saja:
  python3 05_llm_report_multimodel.py --models tinyllama qwen2.5:0.5b

  # Tambahkan OpenRouter sebagai pembanding cloud:
  python3 05_llm_report_multimodel.py --openrouter

  # Semua sekaligus (3 lokal + 1 cloud):
  python3 05_llm_report_multimodel.py --openrouter --all

PRASYARAT:
  ollama serve                    (terminal terpisah)
  ollama pull tinyllama:1.1b
  ollama pull qwen2.5:0.5b
  ollama pull qwen2.5:1.5b
  pip install evaluate rouge-score sacrebleu

REFERENSI:
  Michelet & Breitinger (2024) — LLM untuk laporan forensik
  Studiawan et al. (2025)      — Evaluasi BLEU/ROUGE, 3 skenario
  Chabot et al. (2015)         — ORD2I ontology
"""

import os, sys, json, csv, re, time, argparse
import urllib.request, urllib.error

csv.field_size_limit(10 ** 7)

# ============================================================
# KONFIGURASI
# ============================================================

OLLAMA_BASE_URL  = "http://localhost:11434"
TIMEOUT_GENERATE = 360   # 6 menit — tinyllama bisa lambat
TIMEOUT_CONNECT  = 10

# Tiga model lokal yang akan diuji
LOCAL_MODELS = [
    "tinyllama:1.1b",
    "qwen2.5:0.5b",
    "qwen2.5:1.5b",
]

# OpenRouter (cloud, opsional)
OPENROUTER_API_KEY   = os.environ.get("OPENROUTER_API_KEY", "ISI_API_KEY_ANDA_DI_SINI")
OPENROUTER_BASE_URL  = "https://openrouter.ai/api/v1/chat/completions"
OPENROUTER_TIMEOUT   = 60
OPENROUTER_MODEL     = "qwen/qwen-2.5-7b-instruct"

OUTPUT_DIR = "hasil_sparql"
os.makedirs(OUTPUT_DIR, exist_ok=True)

INPUT_Q2   = os.path.join(OUTPUT_DIR, "Q2_webpage_visits.csv")
INPUT_Q3   = os.path.join(OUTPUT_DIR, "Q3_web_searches.csv")
INPUT_Q4   = os.path.join(OUTPUT_DIR, "Q4_cookie_access.csv")
INPUT_Q6   = os.path.join(OUTPUT_DIR, "Q6_app_execution.csv")
INPUT_Q8   = os.path.join(OUTPUT_DIR, "Q8_registry_mods.csv")
INPUT_Q9   = os.path.join(OUTPUT_DIR, "Q9_system_events.csv")
INPUT_CORR = os.path.join(OUTPUT_DIR, "correlation_results.csv")

# ============================================================
# GROUND TRUTH
# ============================================================

GROUND_TRUTH = """FORENSIC REPORT: Firefox Browser Activity Analysis
Dataset: Zenodo Scenario 1, Windows 11 Enterprise, Date: 2023-12-26

EXECUTIVE SUMMARY:
On 2023-12-26 at approximately 00:35 UTC, a user on a Windows 11 Enterprise
system used Microsoft Edge to search for and download Mozilla Firefox.
Firefox was installed by 00:42 and immediately used to research SQL injection
attack techniques. The user searched for "how to perform sql injection attack"
on Google and visited the W3Schools SQL injection tutorial at 00:46.

TIMELINE OF EVENTS:
1. [00:35] User searched Bing for "mozilla firefox download" using Microsoft Edge
2. [00:36] User visited mozilla.org/en-US/firefox/new to download Firefox
3. [00:37] Firefox Installer.exe downloaded from mozilla.org
4. [00:38-00:43] Firefox installation executed on the Windows 11 system
5. [00:42] Mozilla Firefox browser launched for the first time
6. [00:44] Firefox displayed privacy notice from mozilla.org/privacy/firefox
7. [00:45] User navigated to google.com search engine
8. [00:45] User performed search query: how to perform sql injection attack
9. [00:46] User visited W3Schools SQL injection tutorial: w3schools.com/sql/sql_injection.asp
10. [00:48] Firefox session ended

KEY FORENSIC FINDINGS:
1. The user deliberately searched for SQL injection attack techniques
2. The user visited an SQL injection tutorial at www.w3schools.com/sql/sql_injection.asp
3. Firefox was freshly installed only minutes before the suspicious SQL injection searches
4. The temporal sequence install Firefox then search SQL injection then visit tutorial indicates purposeful activity
5. Google cookies from google.com were set during the session confirming active browsing
6. ORD2I correlation analysis shows score 1.0 for WebSearch to WebpageVisit causal chain
7. Total active Firefox session lasted approximately 6 minutes

CONCLUSION:
The forensic evidence demonstrates deliberate and targeted research into SQL injection
attack methods. The user installed Firefox and within minutes performed a specific
search for SQL injection techniques, then visited an SQL injection tutorial. The
temporal proximity and causal chain identified by ORD2I correlation analysis strongly
suggests purposeful activity rather than casual browsing.
"""

# ============================================================
# FORENSIC DIGEST
# ============================================================

def build_digest():
    """
    Membangun forensic digest LENGKAP dari SELURUH artefak Scenario 1:
    - Browser (Q2, Q3, Q4): webpage visits, searches, cookies
    - App execution (Q6): prefetch, filestat, BAM
    - Registry (Q8): perubahan registry terkait instalasi
    - System events (Q9): logon, task scheduler
    - Korelasi ORD2I: rantai kausal antar event
    - Timeline ringkas kronologis lintas artefak

    MASALAH SEBELUMNYA: digest hanya berisi Q2+Q3+Q4 (browser saja)
    → semua laporan hanya jadi "Analysis of Webpage Visits"
    FIX: tambahkan Q6 (app execution), Q8 (registry), Q9 (system events)
    """
    lines = []
    lines.append("=== FORENSIC EVIDENCE DIGEST — Full Scenario 1 ===")
    lines.append("Dataset : Zenodo Scenario 1 (Studiawan et al., 2025)")
    lines.append("OS      : Windows 11 Enterprise")
    lines.append("Date    : 2023-12-26, session 00:34–00:48 UTC (~14 minutes)")
    lines.append("Sources : Browser SQLite, NTFS filestat, Prefetch, Registry, Event Log")
    lines.append("Ontology: ORD2I (Chabot et al., 2015) — CKL + SKL + TKL")
    lines.append("")

    # ── FASE 1: Edge activity (sebelum Firefox install) ─────────
    lines.append("--- [PHASE 1] EDGE/BING ACTIVITY — Firefox Download (00:34–00:41) ---")
    lines.append("  [00:34:24] APP EXEC  : MSEDGE.EXE [prefetch, run_count=1]")
    lines.append("  [00:35:11] WEB VISIT : microsoft.com/edge/welcome [Edge first launch]")
    lines.append("  [00:35:38] WEB VISIT : bing.com [Edge navigated to Bing]")
    lines.append('  [00:35:56] WEB SEARCH: "mozilla firefox download" [Bing, via Edge]')
    lines.append("  [00:36:45] WEB VISIT : bing.com/ck/a (search result click)")
    lines.append("  [00:37:00] WEB VISIT : mozilla.org/en-US/firefox/download/thanks")
    lines.append("  [00:37:07] WEB VISIT : download.mozilla.org (Firefox stub installer)")
    lines.append("  [00:37:07] FILE DL   : Firefox Installer.exe downloaded from mozilla.org")
    lines.append("")

    # ── FASE 2: Firefox installation (Q6 + Q8) ──────────────────
    lines.append("--- [PHASE 2] FIREFOX INSTALLATION (00:37–00:44) ---")
    # Hanya tampilkan milestone kunci instalasi, bukan semua DLL
    KEY_INSTALL_NAMES = [
        "firefox installer.exe", "firefox installer.exe",
        "setup-stub.exe", "setup-stub",
        "firefox.exe", "firefox.exe",
        "maintenanceservice.exe", "maintenanceservice_installer.exe",
        "default-browser-agent.exe", "helper.exe",
    ]
    if os.path.exists(INPUT_Q6):
        seen_app = set()
        for r in sorted(csv.DictReader(open(INPUT_Q6, encoding="utf-8")),
                        key=lambda x: x.get("timestamp","")):
            ts   = r.get("timestamp","")[:19].replace("T"," ")
            proc = r.get("process_name","").strip()
            fp   = r.get("file_path","").strip()
            et   = r.get("event_type","")
            # Hanya ambil nama executable, bukan path DLL
            name = proc
            if not name:
                # Dari file_path ambil basename
                import os as _os
                bn = _os.path.basename(fp.replace("\\","/"))
                name = bn if bn.endswith(('.exe','.EXE')) else ""
            if not name: continue
            name_lo = name.lower()
            key = name_lo[:40]
            if key in seen_app: continue
            # Filter: hanya Firefox-related executables
            if any(k in name_lo for k in
                   ["firefox installer","firefox.exe","setup-stub",
                    "maintenanceservice","default-browser","helper.exe"]):
                seen_app.add(key)
                parser = r.get("parser","")
                lines.append(f"  [{ts}] {et:<14}: {name[:50]}  [{parser}]")
        lines.append("")

    # Registry entries terkait instalasi
    lines.append("  Registry artifacts (Q8 — Firefox install):")
    if os.path.exists(INPUT_Q8):
        seen_rk = set()
        for r in sorted(csv.DictReader(open(INPUT_Q8, encoding="utf-8")),
                        key=lambda x: x.get("timestamp","")):
            rk  = r.get("registry_key","") or r.get("message","")[:80]
            ts  = r.get("timestamp","")[:19].replace("T"," ")
            if not any(k in rk.lower() for k in ["firefox","mozilla"]): continue
            key = rk[:50]
            if key in seen_rk: continue
            seen_rk.add(key)
            lines.append(f"  [{ts}] REG MODIFY: {rk[:70]}")
            if len(seen_rk) >= 5: break
    lines.append("")

    # ── FASE 3: Firefox browser activity (Q2 + Q3 + Q4) ─────────
    lines.append("--- [PHASE 3] FIREFOX BROWSER ACTIVITY (00:44–00:48) ---")
    seen_url = set()
    if os.path.exists(INPUT_Q2):
        # Hanya URL dari Firefox (bukan Edge)
        for r in sorted(csv.DictReader(open(INPUT_Q2, encoding="utf-8")),
                        key=lambda x: x.get("timestamp","")):
            url = r.get("url","").strip()
            ts  = r.get("timestamp","")[:19].replace("T"," ")
            ttl = r.get("title","").strip()
            if not url or url in seen_url: continue
            # Hanya ambil Firefox session (00:44+)
            if ts >= "2023-12-26 00:44":
                seen_url.add(url)
                t = f" [{ttl}]" if ttl and ttl not in ("nan","") else ""
                lines.append(f"  [{ts}] WEB VISIT : {url[:65]}{t}")
    lines.append("")

    lines.append("  Web searches (Q3):")
    seen_search = set()
    if os.path.exists(INPUT_Q3):
        for r in csv.DictReader(open(INPUT_Q3, encoding="utf-8")):
            url = r.get("url","").strip()
            ts  = r.get("timestamp","")[:19].replace("T"," ")
            m   = re.search(r'[?&](?:q|oq)=([^&]+)', url)
            query = m.group(1).replace("+"," ").replace("%20"," ") if m else ""
            if query and query not in seen_search:
                seen_search.add(query)
                lines.append(f'  [{ts}] WEB SEARCH: "{query}"')
    lines.append("")

    lines.append("  Cookies received (Q4, top 8 unique):")
    seen_ck = set(); cc = 0
    if os.path.exists(INPUT_Q4):
        for r in csv.DictReader(open(INPUT_Q4, encoding="utf-8")):
            ts  = r.get("timestamp","")[:19].replace("T"," ")
            nm  = r.get("cookie_name","").strip()
            dom = r.get("cookie_domain","").strip()
            msg = r.get("message","")
            if not nm:
                mx = re.search(r'(https?://[^\s]+)\s*\(([^)]+)\)', msg)
                if mx: dom, nm = mx.group(1), mx.group(2)
            key = f"{nm[:20]}@{dom[:35]}"
            if key not in seen_ck:
                seen_ck.add(key)
                lines.append(f"  [{ts}] COOKIE    : {nm[:25]} @ {dom[:45]}")
                cc += 1
            if cc >= 8: break
    lines.append("")

    # ── FASE 4: System events (Q9) ───────────────────────────────
    lines.append("--- [PHASE 4] SYSTEM EVENTS (Q9 — Event Log / winevtx) ---")
    if os.path.exists(INPUT_Q9):
        seen_ev = set()
        for r in sorted(csv.DictReader(open(INPUT_Q9, encoding="utf-8")),
                        key=lambda x: x.get("timestamp","")):
            et  = r.get("event_type","")
            ts  = r.get("timestamp","")[:19].replace("T"," ")
            msg = r.get("message","")
            m   = re.search(r'\[(\d+)\s*/\s*(0x[0-9a-fA-F]+)\]', msg)
            eid = m.group(1) if m else "?"
            # Ekstrak source dari message
            src_m = re.search(r'Source Name:\s*([^\[]+)', msg)
            src   = src_m.group(1).strip()[:40] if src_m else ""
            key   = (et, eid)
            if key in seen_ev: continue
            seen_ev.add(key)
            if et == "UserLogon":
                lines.append(f"  [{ts}] {et:<14}: EventCode={eid} {src}")
            elif et == "TaskSchedule":
                lines.append(f"  [{ts}] {et:<14}: EventCode={eid} {msg[:50]}")
            if len(seen_ev) >= 6: break
    lines.append("")

    # ── ORD2I Correlations ───────────────────────────────────────
    lines.append("--- [ORD2I CORRELATIONS] Rantai Kausal Antar Event ---")
    lines.append("  Formula: Corr(e1,e2) = (CorrT + CorrS + CorrO)/3 + CorrEK")
    lines.append("  Window temporal: 300s (browser), 600s (execution)")
    if os.path.exists(INPUT_CORR):
        seen_pair = set(); shown = 0
        corr_path = INPUT_CORR
        # Coba juga versi full
        corr_full = os.path.join(OUTPUT_DIR, "correlation_full_results.csv")
        if os.path.exists(corr_full):
            corr_path = corr_full
        rows_c = sorted(csv.DictReader(open(corr_path, encoding="utf-8")),
                        key=lambda x: float(x.get("score",0)), reverse=True)
        for r in rows_c:
            u1  = r.get("event1_url","") or r.get("event1_app","") or r.get("event1_path","")
            u2  = r.get("event2_url","") or r.get("event2_app","") or r.get("event2_path","")
            t1  = r.get("event1_time","")[:19]
            t2  = r.get("event2_time","")[:19]
            sc  = float(r.get("score",0))
            ek  = r.get("CorrEK","?")
            key = (r.get("event1_type",""), u1[:35], r.get("event2_type",""), u2[:35])
            if key in seen_pair or u1==u2: continue
            seen_pair.add(key)
            lines.append(f"  score={sc:.3f} | CorrEK={ek} | "
                         f"{r.get('event1_type','')} → {r.get('event2_type','')}")
            lines.append(f"    [{t1}] {u1[:65]}")
            lines.append(f"    [{t2}] {u2[:65]}")
            shown += 1
            if shown >= 5: break
    lines.append("")

    # ── KEY FINDINGS ─────────────────────────────────────────────
    lines.append("--- KEY FORENSIC FINDINGS ---")
    lines.append("  1. User used Edge to search and download Firefox (00:35–00:37)")
    lines.append("  2. Firefox installed (setup-stub.exe, 00:37–00:42; registry+filestat+prefetch)")
    lines.append("  3. firefox.exe first run confirmed: prefetch 00:44:03, BAM 00:48:14")
    lines.append("  4. Within 2 minutes of launch: searched 'how to perform sql injection attack'")
    lines.append("  5. Visited W3Schools SQL injection tutorial 23 seconds after search")
    lines.append("  6. ORD2I correlation score=1.000 confirms causal chain (CorrEK=1.0)")
    lines.append("  7. W3Schools cookies (_ga, _sharedID) confirm active page visit")
    lines.append("  8. No evidence of actual attack execution — research/reconnaissance pattern")
    lines.append("  9. Total session duration: ~14 minutes (00:34:22–00:48:28 UTC)")
    lines.append("")
    lines.append("  SUSPECT ACTIVITY: deliberate download of fresh browser then immediate")
    lines.append("  search for SQL injection techniques = potential reconnaissance/learning")

    return "\n".join(lines)




# ============================================================
# PROMPTS
# ============================================================

def prompt_s1(digest):
    return (
        "You are a digital forensic analyst. Write a COMPLETE forensic reconstruction "
        "of the entire incident based on ALL evidence sources below.\n"
        "The evidence covers: Edge browser, Firefox installation, Firefox browsing, "
        "app execution (prefetch), registry changes, and system events.\n"
        "DO NOT focus only on browser visits — reconstruct the FULL 14-minute incident.\n\n"
        f"MULTI-SOURCE EVIDENCE:\n{digest}\n\n"
        "FORENSIC REPORT:\n"
        "EXECUTIVE SUMMARY: [what happened across ALL artifact sources]\n"
        "FULL TIMELINE: [chronological reconstruction from 00:34 to 00:48, "
        "label each event with its artifact source: BROWSER/PREFETCH/REGISTRY/EVTLOG]\n"
        "KEY FINDINGS: [suspicious patterns across ALL sources]\n"
        "CONCLUSION: [user intent assessment with confidence level]"
    )


def prompt_s2(digest):
    corr = (
        "TOP ORD2I CORRELATIONS (cross-artifact):\n"
        "- score=1.000 | CorrEK=1.0: WebSearch → WebpageVisit\n"
        "  [00:45:45] SEARCH 'how to perform sql injection attack' (Firefox SQLite)\n"
        "  [00:46:08] VISIT  www.w3schools.com/sql/sql_injection.asp (Firefox SQLite)\n"
        "  → Causal chain confirmed: direct search → tutorial visit in 23 seconds\n\n"
        "- score=~0.85 | CorrEK=0.9: FileDownload → AppExecution\n"
        "  [00:37:07] Firefox Installer.exe downloaded (Edge cache)\n"
        "  [00:39:14] FIREFOX INSTALLER.EXE executed (prefetch run_count=1)\n"
        "  → Installation chain confirmed cross-artifact\n\n"
        "- score=~0.80 | CorrEK=0.7: AppLaunch → WebpageVisit\n"
        "  [00:44:03] FIREFOX.EXE first run (prefetch)\n"
        "  [00:44:45] VISIT mozilla.org/privacy/firefox (Firefox SQLite)\n"
        "  → Browser launch → first page visit confirmed\n\n"
        "ORD2I TKL: tool=log2timeline/Plaso, confidence=0.9, all Windows 11 parsers\n"
        "ORD2I CorrEK rule: WebSearch followed by non-search WebpageVisit = causal chain"
    )
    return (
        "You are a digital forensic analyst. Write a COMPLETE forensic reconstruction "
        "of the entire incident using ORD2I multi-artifact correlation analysis.\n"
        "Evidence spans: Edge activity, Firefox installation, Firefox browsing, "
        "prefetch execution, registry modifications, event log entries.\n\n"
        f"MULTI-SOURCE EVIDENCE:\n{digest}\n\n"
        f"ORD2I CORRELATION ANALYSIS:\n{corr}\n\n"
        "FORENSIC REPORT:\n"
        "EXECUTIVE SUMMARY: [2–3 sentences covering ALL 4 phases]\n"
        "FULL TIMELINE: [label each event: BROWSER/PREFETCH/REGISTRY/EVTLOG/COOKIE]\n"
        "KEY FINDINGS: [include ORD2I cross-artifact correlation scores]\n"
        "CONCLUSION: [user intent, confidence level, recommended next steps]"
    )


def prompt_s3(digest):
    example = (
        "=== FORMAT EXAMPLE (structure only — do NOT copy dates/URLs/names) ===\n"
        "FORENSIC REPORT -- Full Incident Reconstruction\n"
        "SUMMARY: On [DATE], user on Windows 11 [OS] conducted [action] "
        "starting with [app] and ending with [result].\n"
        "TIMELINE:\n"
        "- [[TIME]] [ARTIFACT SOURCE] [Event description]\n"
        "- [[TIME]] [ARTIFACT SOURCE] [Event description]\n"
        "- [[TIME]] [ARTIFACT SOURCE] [Event description]\n"
        "FINDINGS:\n"
        "1. [Finding from browser evidence]\n"
        "2. [Finding from execution/prefetch evidence]\n"
        "3. [Finding from registry evidence]\n"
        "4. [Suspicious pattern or causal chain]\n"
        "CONCLUSION: [Assessment with confidence level and recommended action]\n"
        "=== END FORMAT ===\n\n"
        "IMPORTANT: Label every timeline entry with its source. "
        "Cover ALL 4 phases: Edge download, Firefox install, Firefox browsing, session end. "
        "Use exact dates and URLs from the evidence. Replace [ARTIFACT SOURCE] with "
        "BROWSER, PREFETCH, REGISTRY, EVTLOG, or COOKIE as appropriate.\n"
    )
    return (
        f"{example}"
        f"MULTI-SOURCE EVIDENCE:\n{digest}\n\n"
        "FORENSIC REPORT -- Full Incident Reconstruction\n"
        "SUMMARY: On 2023-12-26, user on Windows 11 Enterprise"
    )


# ============================================================
# OLLAMA
# ============================================================

def get_ollama_tags():
    """Ambil daftar model yang tersedia di Ollama."""
    try:
        req = urllib.request.Request(f"{OLLAMA_BASE_URL}/api/tags", method="GET")
        with urllib.request.urlopen(req, timeout=TIMEOUT_CONNECT) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        return [m.get("name","") for m in data.get("models",[])]
    except urllib.error.URLError as e:
        raise RuntimeError(
            f"Ollama tidak berjalan! ({e})\n"
            "Jalankan: ollama serve"
        )


def find_model(wanted, available):
    """
    Cari model yang tersedia, cocokkan nama dengan fleksibel.
    Misalnya 'tinyllama:1.1b' cocok dengan 'tinyllama' atau 'tinyllama:1.1b'.
    """
    wanted_base = wanted.split(":")[0].lower()
    wanted_tag  = wanted.split(":")[1].lower() if ":" in wanted else ""

    # Exact match dulu
    for a in available:
        if a.lower() == wanted.lower():
            return a

    # Match base+tag
    for a in available:
        a_base = a.split(":")[0].lower()
        a_tag  = a.split(":")[1].lower() if ":" in a else ""
        if a_base == wanted_base and (not wanted_tag or a_tag == wanted_tag):
            return a

    # Base only match
    for a in available:
        if a.split(":")[0].lower() == wanted_base:
            return a

    return None


def call_ollama(prompt, model):
    sys_msg = (
        "You are a professional digital forensic analyst. "
        "Write structured forensic reports based ONLY on provided evidence. "
        "Do not invent facts, URLs, or timestamps."
    )
    # Coba Python library dulu
    try:
        import ollama as _ol
        resp = _ol.chat(
            model=model,
            messages=[
                {"role":"system","content":sys_msg},
                {"role":"user","content":prompt}
            ],
            options={"temperature":0.1, "num_predict":450}
        )
        return resp.message.content if hasattr(resp,"message") else resp["message"]["content"]
    except ImportError:
        pass
    except Exception as e:
        print(f"    [WARN] ollama lib ({e}), fallback HTTP")

    # Fallback HTTP
    payload = json.dumps({
        "model": model,
        "messages": [
            {"role":"system","content":sys_msg},
            {"role":"user","content":prompt}
        ],
        "stream": False,
        "options": {"temperature":0.1, "num_predict":450}
    }).encode("utf-8")
    req = urllib.request.Request(
        f"{OLLAMA_BASE_URL}/api/chat", data=payload,
        headers={"Content-Type":"application/json"}, method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT_GENERATE) as resp:
            result = json.loads(resp.read().decode("utf-8"))
            return result.get("message",{}).get("content","[ERROR] Empty")
    except urllib.error.URLError as e:
        if "timed out" in str(e).lower():
            return f"[ERROR] Timeout {TIMEOUT_GENERATE}s — coba model lebih kecil"
        return f"[ERROR] {e}"


# ============================================================
# OPENROUTER
# ============================================================

def call_openrouter(prompt, model, api_key):
    sys_msg = (
        "You are a professional digital forensic analyst. "
        "Write clear, structured forensic reports based ONLY on "
        "the provided evidence. Do not invent facts. Be concise."
    )
    payload = json.dumps({
        "model": model,
        "messages": [
            {"role":"system","content":sys_msg},
            {"role":"user","content":prompt}
        ],
        "temperature":0.1, "max_tokens":500,
    }).encode("utf-8")
    req = urllib.request.Request(
        OPENROUTER_BASE_URL, data=payload,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type":  "application/json",
            "HTTP-Referer":  "https://github.com/ord2i-thesis",
            "X-Title":       "ORD2I Forensic Pipeline",
        }, method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=OPENROUTER_TIMEOUT) as resp:
            data    = json.loads(resp.read().decode("utf-8"))
            choices = data.get("choices",[])
            if not choices:
                return f"[ERROR] {data.get('error',{}).get('message','No choices')}"
            content = choices[0].get("message",{}).get("content","")
            usage   = data.get("usage",{})
            if usage:
                print(f"    [tokens] prompt={usage.get('prompt_tokens',0)} "
                      f"completion={usage.get('completion_tokens',0)}")
            return content or "[ERROR] Empty"
    except urllib.error.HTTPError as e:
        codes = {401:"401 Unauthorized",402:"402 kredit habis",429:"429 rate limit"}
        return f"[ERROR] {codes.get(e.code,f'HTTP {e.code}')}"
    except urllib.error.URLError as e:
        return f"[ERROR] Network: {e}"


# ============================================================
# EVALUASI BLEU/ROUGE
# ============================================================

def evaluate(hypothesis, reference):
    if not hypothesis or hypothesis.strip().startswith("[ERROR]"):
        return {"bleu":0.0,"rouge1":0.0,"rouge2":0.0,"rougeL":0.0,"method":"error"}

    try:
        import evaluate as ev
        bleu  = ev.load("bleu")
        rouge = ev.load("rouge")
        b = bleu.compute(predictions=[hypothesis], references=[[reference]])
        r = rouge.compute(predictions=[hypothesis], references=[reference])
        return {
            "bleu":   round(b.get("bleu",0),  4),
            "rouge1": round(r.get("rouge1",0), 4),
            "rouge2": round(r.get("rouge2",0), 4),
            "rougeL": round(r.get("rougeL",0), 4),
            "method": "evaluate",
        }
    except ImportError:
        print("    [WARN] library 'evaluate' tidak ada — word-overlap fallback")
        print("           Install: pip install evaluate rouge-score sacrebleu")
        hw = set(hypothesis.lower().split())
        rw = set(reference.lower().split())
        ov  = len(hw & rw)
        pr  = ov/len(hw) if hw else 0
        rc  = ov/len(rw) if rw else 0
        f1  = 2*pr*rc/(pr+rc) if (pr+rc)>0 else 0
        return {"bleu":round(pr,4),"rouge1":round(f1,4),"rouge2":0.0,
                "rougeL":round(f1,4),"method":"word-overlap"}


# ============================================================
# RUNNER — jalankan 3 skenario untuk 1 model
# ============================================================

def run_one_model(model_label, model_id, call_fn, digest):
    """
    Jalankan S1, S2, S3 untuk satu model.
    Kembalikan list 3 result dicts.
    """
    print(f"\n  {'─'*56}")
    print(f"  MODEL: {model_label}")
    print(f"  {'─'*56}")

    prompts = [
        ("S1_without_knowledge", "S1 — Tanpa knowledge", prompt_s1(digest)),
        ("S2_with_knowledge",    "S2 — Dengan ORD2I",   prompt_s2(digest)),
        ("S3_few_shot",          "S3 — Few-shot",       prompt_s3(digest)),
    ]

    results = []
    prefix = re.sub(r'[^a-z0-9]', '_', model_label.lower())[:20]

    for sc_key, sc_desc, sc_prompt in prompts:
        print(f"\n  [{sc_key}]  {len(sc_prompt)} char")
        t0     = time.time()
        output = call_fn(sc_prompt)
        secs   = round(time.time() - t0, 1)
        is_err = output.strip().startswith("[ERROR]")

        if is_err:
            print(f"  ❌ GAGAL: {output[:200]}")
        else:
            print(f"  ✅ {len(output)} char dalam {secs}s")
            print("  " + output[:250].replace("\n","\n  "))
            print("  ...")

        scores = evaluate(output, GROUND_TRUTH)
        mean_s = round((scores["bleu"]+scores["rouge1"]+scores["rouge2"]+scores["rougeL"])/4, 4)
        method = scores.pop("method","?")
        print(f"  BLEU={scores['bleu']:.4f} R1={scores['rouge1']:.4f} "
              f"R2={scores['rouge2']:.4f} RL={scores['rougeL']:.4f} "
              f"Mean={mean_s:.4f}  [{method}]")

        # Simpan file laporan
        fname = os.path.join(OUTPUT_DIR, f"{prefix}_{sc_key}_report.txt")
        with open(fname, "w", encoding="utf-8") as f:
            f.write(f"=== {sc_desc} ===\n")
            f.write(f"Provider : Ollama\n")
            f.write(f"Model    : {model_id}\n")
            f.write(f"Waktu    : {secs}s\n")
            f.write(f"Metode   : {method}\n")
            f.write(f"BLEU     : {scores['bleu']:.4f}\n")
            f.write(f"ROUGE-1  : {scores['rouge1']:.4f}\n")
            f.write(f"ROUGE-2  : {scores['rouge2']:.4f}\n")
            f.write(f"ROUGE-L  : {scores['rougeL']:.4f}\n")
            f.write(f"Mean     : {mean_s:.4f}\n")
            f.write("="*60+"\n\n")
            f.write(output)
        print(f"  Disimpan: {fname}")

        results.append({
            "provider":    "Ollama",
            "model":       model_id,
            "scenario":    sc_key,
            "bleu":        scores["bleu"],
            "rouge1":      scores["rouge1"],
            "rouge2":      scores["rouge2"],
            "rougeL":      scores["rougeL"],
            "mean":        mean_s,
            "output_len":  len(output),
            "time_s":      secs,
            "success":     not is_err,
            "eval_method": method,
        })
    return results


# ============================================================
# TABEL HASIL
# ============================================================

def print_table(all_results):
    print(f"\n{'='*92}")
    print("TABEL EVALUASI LLM — Studiawan et al. (2025) Format")
    print(f"{'='*92}")
    print(f"{'Provider/Model':<28} {'Skenario':<22} "
          f"{'BLEU':>7} {'R-1':>7} {'R-2':>7} {'R-L':>7} {'Mean':>7} {'t':>5} {'Metode'}")
    print(f"{'─'*92}")

    prev = ""
    for r in all_results:
        label = f"{r['provider']} ({r['model']})"[:26]
        sc    = r['scenario'][:20]
        flag  = "" if r['success'] else " ✗"
        if label != prev and prev:
            print(f"{'─'*92}")
        prev = label
        print(f"{label:<28} {sc:<22} "
              f"{r['bleu']:>7.4f} {r['rouge1']:>7.4f} {r['rouge2']:>7.4f} "
              f"{r['rougeL']:>7.4f} {r['mean']:>7.4f} "
              f"{r['time_s']:>4.0f}s {r.get('eval_method','?')}{flag}")

    print(f"{'='*92}")

    # Ringkasan per model
    print("\nRINGKASAN — Rata-rata Mean per Model:")
    models_seen = []
    for r in all_results:
        key = (r['provider'], r['model'])
        if key not in models_seen:
            models_seen.append(key)

    for prov, mod in models_seen:
        subset = [r for r in all_results if r['provider']==prov and r['model']==mod]
        if not subset: continue
        avg = round(sum(r['mean'] for r in subset)/len(subset), 4)
        best_sc = max(subset, key=lambda x: x['mean'])
        n_ok = sum(1 for r in subset if r['success'])
        print(f"  {prov} ({mod}): Mean rata-rata={avg:.4f} | "
              f"Terbaik={best_sc['scenario']} ({best_sc['mean']:.4f}) | "
              f"{n_ok}/3 skenario OK")


# ============================================================
# MAIN
# ============================================================

def main():
    ap = argparse.ArgumentParser(
        description="Step 5 — LLM Report: 3 Model Lokal + OpenRouter"
    )
    ap.add_argument("--models", nargs="+", default=None,
        help="Model spesifik (default: semua 3 lokal). "
             "Contoh: --models tinyllama qwen2.5:0.5b")
    ap.add_argument("--openrouter", action="store_true",
        help="Tambahkan OpenRouter cloud sebagai pembanding")
    ap.add_argument("--all", action="store_true",
        help="Jalankan semua: 3 lokal + OpenRouter")
    args = ap.parse_args()

    # Tentukan model yang akan dijalankan
    target_models = args.models if args.models else LOCAL_MODELS
    run_openrouter = args.openrouter or args.all

    print("=" * 60)
    print("STEP 5 — Pelaporan LLM Multi-Model")
    print(f"  Model lokal : {', '.join(target_models)}")
    print(f"  OpenRouter  : {'Ya' if run_openrouter else 'Tidak'}")
    print("=" * 60)

    # Cek Ollama
    print("\n[1] Memeriksa Ollama...")
    try:
        available = get_ollama_tags()
        print(f"    Model tersedia: {available}")
    except RuntimeError as e:
        print(f"\n    ❌ {e}")
        return

    # Build digest
    print("\n[2] Membangun forensic digest...")
    digest = build_digest()
    print(f"    ✅ {len(digest)} karakter")

    all_results = []
    skipped     = []

    # ── Jalankan setiap model lokal ─────────────────────────
    print(f"\n[3] Menjalankan {len(target_models)} model lokal...")

    for wanted in target_models:
        actual = find_model(wanted, available)
        if not actual:
            print(f"\n  ⚠  Model '{wanted}' tidak ditemukan di Ollama!")
            print(f"     Download: ollama pull {wanted}")
            skipped.append(wanted)
            continue

        print(f"\n  ✅ '{wanted}' → '{actual}'")
        results = run_one_model(
            model_label=actual,
            model_id=actual,
            call_fn=lambda p, m=actual: call_ollama(p, m),
            digest=digest,
        )
        all_results.extend(results)

    # ── OpenRouter (opsional) ─────────────────────────────
    if run_openrouter:
        print(f"\n[4] Menjalankan OpenRouter ({OPENROUTER_MODEL})...")
        api_key = OPENROUTER_API_KEY
        if not api_key or api_key == "ISI_API_KEY_ANDA_DI_SINI" or len(api_key) < 20:
            print("    ❌ API key belum diset!")
            print("       export OPENROUTER_API_KEY='sk-or-v1-...'")
        else:
            print(f"    API key: ...{api_key[-6:]}")

            def or_call(p):
                return call_openrouter(p, OPENROUTER_MODEL, api_key)

            results_or = run_one_model(
                model_label=f"OpenRouter ({OPENROUTER_MODEL})",
                model_id=OPENROUTER_MODEL,
                call_fn=or_call,
                digest=digest,
            )
            # Tandai provider sebagai OpenRouter
            for r in results_or:
                r["provider"] = "OpenRouter"
            all_results.extend(results_or)

    if not all_results:
        print("\n❌ Tidak ada hasil. Pastikan Ollama berjalan dan model sudah didownload.")
        return

    # Tampilkan tabel
    print_table(all_results)

    # Simpan CSV
    csv_path = os.path.join(OUTPUT_DIR, "llm_evaluation_results.csv")
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=all_results[0].keys())
        w.writeheader()
        w.writerows(all_results)
    print(f"\n✅ CSV: {csv_path}")

    # Ringkasan akhir
    n_ok   = sum(1 for r in all_results if r['success'])
    n_tot  = len(all_results)
    n_skip = len(skipped)
    print(f"✅ {n_ok}/{n_tot} skenario berhasil")
    if skipped:
        print(f"⚠  Model tidak ditemukan: {', '.join(skipped)}")
        print(f"   Download: ollama pull {' '.join(skipped)}")
    print("\n✅ Pipeline ORD2I Step 1-5 selesai.")


if __name__ == "__main__":
    main()
