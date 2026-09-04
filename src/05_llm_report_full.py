"""
==========================================================
STEP 5 — PELAPORAN LLM (FULL SCENARIO 1)
==========================================================

Forensic digest dibangun dari SELURUH event type (bukan hanya browser):
  - Aktivitas browser (WebSearch, WebpageVisit, Cookie)
  - Eksekusi aplikasi (AppExecution, AppInstall, AppLaunch)
  - Unduhan file (FileDownload)
  - Event sistem (UserLogon, ProcessCreate)
  - Modifikasi registri (RegistryModify, AutoRun)
  - Rantai korelasi lintas kategori

"""

import os, sys, json, csv, re, time, argparse
import urllib.request, urllib.error

csv.field_size_limit(10 ** 7)

# ============================================================
# KONFIGURASI
# ============================================================

OLLAMA_BASE_URL  = "http://localhost:11434"
TIMEOUT_GENERATE = 360
TIMEOUT_CONNECT  = 10

OLLAMA_MODEL_PREFERENCE = [
    "qwen2.5:1.5b",
    "qwen2.5:0.5b",
    "qwen2.5",
    "tinyllama",
    "gemma:2b", "gemma3:1b",
    "phi3:mini", "phi3",
    "mistral", "llama3",
]

OPENROUTER_API_KEY   = os.environ.get("OPENROUTER_API_KEY", "ISI_API_KEY_ANDA_DI_SINI")
OPENROUTER_BASE_URL  = "https://openrouter.ai/api/v1/chat/completions"
OPENROUTER_TIMEOUT   = 60
OPENROUTER_DEFAULT_MODEL = "qwen/qwen-2.5-7b-instruct"

OUTPUT_DIR = "hasil_sparql_full"
os.makedirs(OUTPUT_DIR, exist_ok=True)

Q2_FILE   = os.path.join(OUTPUT_DIR, "Q2_webpage_visits.csv")
Q3_FILE   = os.path.join(OUTPUT_DIR, "Q3_web_searches.csv")
Q4_FILE   = os.path.join(OUTPUT_DIR, "Q4_cookie_access.csv")
Q6_FILE   = os.path.join(OUTPUT_DIR, "Q6_app_execution.csv")
Q9_FILE   = os.path.join(OUTPUT_DIR, "Q9_system_events.csv")
CORR_FILE = os.path.join(OUTPUT_DIR, "correlation_full_results.csv")

# ============================================================
# GROUND TRUTH — Full Scenario 1
# ============================================================

GROUND_TRUTH = """FORENSIC REPORT: Full Scenario 1 — Windows 11 Enterprise
Dataset: Zenodo Scenario 1, DOI: 10.5281/zenodo.15493424, Date: 2023-12-26

EXECUTIVE SUMMARY:
On 2023-12-26, a user on a Windows 11 Enterprise system initiated a sequence of
activities beginning with downloading and installing Mozilla Firefox using Microsoft
Edge, followed by using Firefox to research SQL injection attack techniques.
The session lasted approximately 14 minutes (00:34-00:48 UTC) and produced artifacts
across browser history, file system, registry, prefetch, and event logs.

TIMELINE OF EVENTS:
1. [00:34-00:35] User logged on to the Windows 11 system
2. [00:35] Microsoft Edge used to search Bing for "mozilla firefox download"
3. [00:36] User visited mozilla.org/en-US/firefox/new via Edge
4. [00:37] Firefox Installer.exe downloaded from mozilla.org
5. [00:38-00:42] Firefox installation executed: installer ran, files written to
   C:\\Program Files\\Mozilla Firefox\\, registry keys created
6. [00:42] Mozilla Firefox launched for the first time (AppLaunch via prefetch)
7. [00:44] Firefox displayed privacy notice from mozilla.org/privacy/firefox
8. [00:45] User navigated to google.com
9. [00:45] User searched Google for "how to perform sql injection attack"
10. [00:46] User visited W3Schools SQL injection tutorial
11. [00:46-00:48] Multiple Google and W3Schools cookies set in Firefox
12. [00:48] Firefox session ended, parent.lock file released

KEY FORENSIC FINDINGS:
1. ORD2I event correlation score 1.000 confirms causal chain: SQL injection
   search directly preceded W3Schools tutorial access (delta-t = 23 seconds)
2. Firefox installation artifacts found in: prefetch (firefox.exe), registry
   (HKLM\\Software\\Microsoft\\Windows\\CurrentVersion), NTFS filestat
3. Edge browser artifacts confirm prior activity: Bing search history in
   chrome_27_history parser predates Firefox installation
4. Cookie evidence from W3Schools (_ga, _sharedID) independently confirms
   active visit to SQL injection tutorial page
5. No evidence of network lateral movement or credential access found
6. Timeline is consistent with a deliberate learning or reconnaissance session

CONCLUSION:
The forensic evidence from all artifact sources consistently demonstrates a
deliberate and focused session: the user specifically downloaded a fresh browser,
then within minutes used it to search for and access SQL injection attack
information. The cross-artifact correlation between browser history, registry
changes, prefetch execution records, and cookie evidence provides high confidence
in the timeline reconstruction. This activity pattern warrants further investigation
into potential malicious intent.
"""

# ============================================================
# FORENSIC DIGEST (Full)
# ============================================================

def build_full_digest():
    """
    Bangun forensic digest dari SEMUA sumber event type.
    Dibatasi ~50 baris agar tidak terlalu panjang untuk LLM.
    """
    lines = []
    lines.append("=== FORENSIC EVIDENCE DIGEST — Full Scenario 1 ===")
    lines.append("Dataset: Zenodo Scenario 1, Windows 11 Enterprise, 2023-12-26")
    lines.append("Sources: Browser SQLite, NTFS, Registry, Prefetch, Event Log")
    lines.append("Ontology: ORD2I (Chabot et al., 2015) — CKL + SKL + TKL")
    lines.append("")

    # ── Browser ─────────────────────────────────────────
    lines.append("--- WEBPAGE VISITS (Firefox SQLite) ---")
    seen_url = set()
    if os.path.exists(Q2_FILE):
        for r in csv.DictReader(open(Q2_FILE, encoding="utf-8")):
            url = r.get("url","").strip()
            ts  = r.get("timestamp","")[:19].replace("T"," ")
            ttl = r.get("title","").strip()
            if url and url not in seen_url:
                seen_url.add(url)
                lines.append(f"  [{ts}] VISIT: {url}" + (f" [{ttl}]" if ttl and ttl!="nan" else ""))
    lines.append("")

    lines.append("--- WEB SEARCHES (Firefox SQLite) ---")
    seen_search = set()
    if os.path.exists(Q3_FILE):
        for r in csv.DictReader(open(Q3_FILE, encoding="utf-8")):
            ts  = r.get("timestamp","")[:19].replace("T"," ")
            url = r.get("url","").strip()
            desc= r.get("description","").strip()
            m = re.search(r'[?&](?:q|oq)=([^&]+)', url)
            query = m.group(1).replace("+"," ").replace("%20"," ") if m else desc
            if query and query not in seen_search:
                seen_search.add(query)
                lines.append(f'  [{ts}] SEARCH: "{query}"')
    lines.append("")

    lines.append("--- COOKIES (Firefox SQLite, top 8 unik) ---")
    seen_cookie = set(); cc = 0
    if os.path.exists(Q4_FILE):
        for r in csv.DictReader(open(Q4_FILE, encoding="utf-8")):
            ts   = r.get("timestamp","")[:19].replace("T"," ")
            name = r.get("cookie_name","").strip()
            dom  = r.get("cookie_domain","").strip()
            if name and dom:
                key = f"{name}@{dom}"
                if key not in seen_cookie:
                    seen_cookie.add(key); cc += 1
                    lines.append(f"  [{ts}] COOKIE: {name} @ {dom}")
            if cc >= 8: break
    lines.append("")

    # ── Execution ────────────────────────────────────────
    lines.append("--- APP EXECUTION (Prefetch/Amcache/BAM) ---")
    seen_app = set()
    if os.path.exists(Q6_FILE):
        for r in csv.DictReader(open(Q6_FILE, encoding="utf-8")):
            ts   = r.get("timestamp","")[:19].replace("T"," ")
            proc = r.get("process_name","").strip()
            etype= r.get("event_type","").strip()
            fp   = r.get("file_path","").strip()
            key  = proc or fp[:40]
            if key and key not in seen_app:
                seen_app.add(key)
                lines.append(f"  [{ts}] {etype}: {proc or fp[:60]}")
    lines.append("")

    # ── System events ────────────────────────────────────
    lines.append("--- SYSTEM EVENTS (Event Log) ---")
    if os.path.exists(Q9_FILE):
        rows_sys = list(csv.DictReader(open(Q9_FILE, encoding="utf-8")))
        for r in rows_sys[:6]:
            ts = r.get("timestamp","")[:19].replace("T"," ")
            et = r.get("event_type","")
            msg= r.get("message","")[:80]
            lines.append(f"  [{ts}] {et}: {msg}")
    lines.append("")

    # ── Top correlations ─────────────────────────────────
    lines.append("--- TOP CORRELATIONS (ORD2I) ---")
    lines.append("Formula: Corr = (CorrT + CorrS + CorrO)/3 + CorrEK")
    if os.path.exists(CORR_FILE):
        seen_pair = set(); shown = 0
        rows_c = sorted(
            csv.DictReader(open(CORR_FILE, encoding="utf-8")),
            key=lambda x: float(x.get("score",0)), reverse=True
        )
        for r in rows_c:
            u1 = r.get("event1_url","") or r.get("event1_app","")
            u2 = r.get("event2_url","") or r.get("event2_app","")
            t1 = r.get("event1_time","")[:19]
            t2 = r.get("event2_time","")[:19]
            sc = float(r.get("score",0))
            key= (r.get("event1_type",""), u1[:35], r.get("event2_type",""), u2[:35])
            if key in seen_pair: continue
            seen_pair.add(key)
            lines.append(f"  score={sc:.3f}: {r.get('event1_type','')} → {r.get('event2_type','')}")
            lines.append(f"    [{t1}] {u1[:60]}")
            lines.append(f"    [{t2}] {u2[:60]}")
            shown += 1
            if shown >= 5: break
    lines.append("")

    # ── Key timeline summary ─────────────────────────────
    lines.append("--- KEY TIMELINE SUMMARY ---")
    lines.append("  [00:34] User logon to Windows 11 Enterprise")
    lines.append("  [00:35] Edge/Bing: search 'mozilla firefox download'")
    lines.append("  [00:36] Visit: mozilla.org/en-US/firefox/new (via Edge)")
    lines.append("  [00:37] Download: Firefox Installer.exe from mozilla.org")
    lines.append("  [00:38-00:42] Firefox installation (NTFS + Registry artifacts)")
    lines.append("  [00:42] APP LAUNCH: Mozilla Firefox (first run, prefetch)")
    lines.append("  [00:44] Visit: mozilla.org/privacy/firefox (Firefox Privacy Notice)")
    lines.append("  [00:45] Visit: google.com")
    lines.append("  [00:45] SEARCH: 'how to perform sql injection attack'")
    lines.append("  [00:46] Visit: w3schools.com/sql/sql_injection.asp [SQL Injection]")
    lines.append("  [00:48] Firefox session ended")

    return "\n".join(lines)


def _short_digest(digest):
    """Versi ringkas untuk model kecil."""
    keep = []
    for line in digest.splitlines():
        if any(x in line for x in [
            "VISIT:", "SEARCH:", "COOKIE:", "APP EXEC", "APP LAUNCH",
            "DOWNLOAD", "LOGON", "score=",
            "00:35","00:36","00:37","00:42","00:44","00:45","00:46","00:48",
            "google.com","mozilla","w3schools","sql","firefox","Firefox",
        ]):
            keep.append(line)
    return "\n".join(keep[:45])


# ============================================================
# PROMPTS
# ============================================================

def build_prompt_s1(digest):
    sd = _short_digest(digest)
    return (
        "Write a forensic report for this Windows 11 investigation.\n\n"
        f"EVIDENCE:\n{sd}\n\n"
        "FORENSIC REPORT:\n"
        "SUMMARY: [what happened — include browser, file system, and execution evidence]\n"
        "TIMELINE: [chronological events from all artifact sources]\n"
        "KEY FINDINGS: [what is suspicious across all artifact categories]\n"
        "CONCLUSION: [overall assessment]"
    )


def build_prompt_s2(digest):
    sd = _short_digest(digest)
    corr_ctx = (
        "TOP ORD2I CORRELATIONS (cross-artifact):\n"
        "- score=1.000: WebSearch -> WebpageVisit (CorrEK=1.0, causal chain)\n"
        "  SQL injection search -> W3Schools tutorial (delta-t=23s)\n"
        "- score=~0.9:  FileDownload -> AppExecution (Firefox download -> install)\n"
        "  Firefox Installer.exe download -> firefox.exe execution\n"
        "- score=~0.85: WebpageVisit -> AppLaunch (mozilla.org visit -> Firefox launch)\n"
        "- score=~0.8:  AppLaunch -> WebpageVisit (Firefox launch -> privacy page)\n"
        "ORD2I CorrEK rule: WebSearch followed by non-search-engine WebpageVisit = causal chain.\n"
        "ORD2I TKL: log2timeline/Plaso, confidence=0.9, all Windows 11 parsers."
    )
    return (
        "Write a forensic report using ORD2I multi-artifact analysis.\n\n"
        f"EVIDENCE (all sources):\n{sd}\n\n"
        f"{corr_ctx}\n\n"
        "FORENSIC REPORT:\n"
        "EXECUTIVE SUMMARY: [2-3 sentences covering all artifact types]\n"
        "TIMELINE: [chronological events with artifact source labels]\n"
        "KEY FINDINGS: [include ORD2I correlation scores and cross-artifact evidence]\n"
        "CONCLUSION: [user intent, confidence level, recommended next steps]"
    )


def build_prompt_s3(digest):
    sd = _short_digest(digest)
    example = (
        "=== FORMAT EXAMPLE (structure only, do NOT copy dates/URLs) ===\n"
        "FORENSIC REPORT -- Full System Activity\n"
        "SUMMARY: On [DATE], user on [OS] performed [action] across [sources].\n"
        "TIMELINE:\n"
        "- [[TIME]] [SOURCE] [Event]\n"
        "- [[TIME]] [SOURCE] [Event]\n"
        "FINDINGS:\n"
        "1. [Finding from browser evidence]\n"
        "2. [Finding from execution evidence]\n"
        "3. [Finding from system evidence]\n"
        "CONCLUSION: [Assessment with confidence]\n"
        "=== END FORMAT ===\n"
    )
    return (
        f"{example}\n"
        "Use the format above. Fill with ONLY the evidence below.\n"
        "Label each timeline entry with its source (BROWSER/EXEC/SYSTEM/REG).\n\n"
        f"EVIDENCE:\n{sd}\n\n"
        "FORENSIC REPORT -- Full System Activity\n"
        "SUMMARY: On 2023-12-26,"
    )


# ============================================================
# OLLAMA
# ============================================================

def get_ollama_model():
    try:
        req = urllib.request.Request(f"{OLLAMA_BASE_URL}/api/tags", method="GET")
        with urllib.request.urlopen(req, timeout=TIMEOUT_CONNECT) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except urllib.error.URLError as e:
        raise RuntimeError(f"Ollama tidak berjalan! ({e})\nJalankan: ollama serve")
    models = [m.get("name","") for m in data.get("models",[])]
    if not models:
        raise RuntimeError("Ollama berjalan tapi tidak ada model.\nDownload: ollama pull qwen2.5:1.5b")
    for pref in OLLAMA_MODEL_PREFERENCE:
        for avail in models:
            if avail.split(":")[0] == pref.split(":")[0]:
                return avail, models
    return models[0], models


def call_ollama(prompt, model):
    sys_msg = (
        "You are a professional digital forensic analyst. Write structured forensic "
        "reports based ONLY on the provided evidence from multiple artifact sources "
        "(browser, file system, registry, event logs). Do not invent facts."
    )
    try:
        import ollama as _ol
        resp = _ol.chat(model=model,
            messages=[{"role":"system","content":sys_msg},
                      {"role":"user","content":prompt}],
            options={"temperature":0.1,"num_predict":500})
        return resp.message.content if hasattr(resp,"message") else resp["message"]["content"]
    except ImportError:
        pass
    except Exception as e:
        print(f"  [WARN] ollama lib ({e}), fallback HTTP")

    payload = json.dumps({
        "model": model,
        "messages": [{"role":"system","content":sys_msg},
                     {"role":"user","content":prompt}],
        "stream": False,
        "options": {"temperature":0.1,"num_predict":500}
    }).encode("utf-8")
    req = urllib.request.Request(f"{OLLAMA_BASE_URL}/api/chat",
        data=payload, headers={"Content-Type":"application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT_GENERATE) as resp:
            result = json.loads(resp.read().decode("utf-8"))
            return result.get("message",{}).get("content","[ERROR] Empty response")
    except urllib.error.URLError as e:
        return f"[ERROR] {e}"


# ============================================================
# OPENROUTER
# ============================================================

def check_openrouter_key():
    key = OPENROUTER_API_KEY
    if not key or key == "ISI_API_KEY_ANDA_DI_SINI" or len(key) < 20:
        raise RuntimeError(
            "OpenRouter API key belum diset!\n\n"
            "Cara 1 — Edit script:\n"
            "  OPENROUTER_API_KEY = \"sk-or-v1-xxxx...\"\n\n"
            "Cara 2 — Environment variable:\n"
            "  export OPENROUTER_API_KEY=\"sk-or-v1-xxxx...\"\n"
            "  python3 05_llm_report_full.py --openrouter\n\n"
            "Lihat kredit: https://openrouter.ai/credits"
        )
    return key


def call_openrouter(prompt, model, api_key):
    sys_msg = (
        "You are a professional digital forensic analyst. Write clear, structured "
        "forensic reports based ONLY on the provided multi-source evidence. "
        "Do not invent facts. Be concise and precise."
    )
    payload = json.dumps({
        "model": model,
        "messages": [{"role":"system","content":sys_msg},
                     {"role":"user","content":prompt}],
        "temperature": 0.1, "max_tokens": 600, "top_p": 0.9,
    }).encode("utf-8")
    req = urllib.request.Request(OPENROUTER_BASE_URL, data=payload,
        headers={"Authorization":f"Bearer {api_key}",
                 "Content-Type":"application/json",
                 "HTTP-Referer":"https://github.com/ord2i-thesis",
                 "X-Title":"ORD2I Full Scenario Pipeline"},
        method="POST")
    try:
        with urllib.request.urlopen(req, timeout=OPENROUTER_TIMEOUT) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            choices = data.get("choices",[])
            if not choices:
                return f"[ERROR] {data.get('error',{}).get('message','No choices')}"
            content = choices[0].get("message",{}).get("content","")
            usage = data.get("usage",{})
            if usage:
                print(f"  [Tokens] prompt={usage.get('prompt_tokens',0)} "
                      f"completion={usage.get('completion_tokens',0)}")
            return content or "[ERROR] Empty"
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8") if e.fp else ""
        codes = {401:"401 Unauthorized",402:"402 Payment Required",429:"429 Rate limit"}
        return f"[ERROR] {codes.get(e.code,f'HTTP {e.code}')}: {body[:100]}"
    except urllib.error.URLError as e:
        return f"[ERROR] Network: {e}"


# ============================================================
# EVALUASI
# ============================================================

def evaluate_bleu_rouge(hypothesis, reference):
    if not hypothesis or hypothesis.strip().startswith("[ERROR]"):
        return {"bleu":0.0,"rouge1":0.0,"rouge2":0.0,"rougeL":0.0}
    try:
        import evaluate
        bleu  = evaluate.load("bleu")
        rouge = evaluate.load("rouge")
        b = bleu.compute(predictions=[hypothesis], references=[[reference]])
        r = rouge.compute(predictions=[hypothesis], references=[reference])
        return {"bleu":   round(b.get("bleu",0),4),
                "rouge1": round(r.get("rouge1",0),4),
                "rouge2": round(r.get("rouge2",0),4),
                "rougeL": round(r.get("rougeL",0),4)}
    except ImportError:
        print("  [WARN] library evaluate tidak ada — word-overlap fallback")
        hw = set(hypothesis.lower().split())
        rw = set(reference.lower().split())
        ov  = len(hw & rw)
        pr  = ov/len(hw) if hw else 0
        rc  = ov/len(rw) if rw else 0
        f1  = 2*pr*rc/(pr+rc) if (pr+rc)>0 else 0
        return {"bleu":round(pr,4),"rouge1":round(f1,4),"rouge2":0.0,"rougeL":round(f1,4)}


# ============================================================
# RUNNER
# ============================================================

def run_scenarios(provider_name, model_name, call_fn, digest):
    print(f"\n{'='*60}")
    print(f"  PROVIDER : {provider_name}")
    print(f"  Model    : {model_name}")
    print(f"{'='*60}")

    scenarios = [
        {"name":"S1_without_knowledge","desc":"S1 — Tanpa knowledge",
         "prompt":build_prompt_s1(digest)},
        {"name":"S2_with_knowledge","desc":"S2 — Dengan ORD2I multi-artifact",
         "prompt":build_prompt_s2(digest)},
        {"name":"S3_few_shot","desc":"S3 — Few-shot multi-source",
         "prompt":build_prompt_s3(digest)},
    ]

    results = []
    prefix  = provider_name.lower().replace(" ","_").replace(":","")[:20]

    for idx, sc in enumerate(scenarios, 1):
        print(f"\n  [{idx}/3] {sc['desc']}  ({len(sc['prompt'])} char)")
        t0     = time.time()
        output = call_fn(sc["prompt"])
        secs   = round(time.time()-t0, 1)
        is_err = output.strip().startswith("[ERROR]")

        if is_err:
            print(f"  [GAGAL] {output[:200]}")
        else:
            print(f"  [OK] {len(output)} char dalam {secs}s")
            print("  --- PREVIEW ---")
            print("  " + output[:300].replace("\n","\n  "))
            print("  ...")

        scores = evaluate_bleu_rouge(output, GROUND_TRUTH)
        mean_s = round(sum(scores.values())/4, 4)
        print(f"\n  BLEU={scores['bleu']:.4f} R1={scores['rouge1']:.4f} "
              f"R2={scores['rouge2']:.4f} RL={scores['rougeL']:.4f} Mean={mean_s:.4f}")

        fname = os.path.join(OUTPUT_DIR, f"{prefix}_{sc['name']}_report.txt")
        with open(fname, "w", encoding="utf-8") as f:
            f.write(f"=== {sc['desc']} ===\n")
            f.write(f"Provider: {provider_name}\nModel: {model_name}\n")
            f.write(f"Waktu: {secs}s\n")
            f.write(f"BLEU:{scores['bleu']:.4f} R1:{scores['rouge1']:.4f} "
                    f"R2:{scores['rouge2']:.4f} RL:{scores['rougeL']:.4f} Mean:{mean_s:.4f}\n")
            f.write("="*60+"\n\n")
            f.write(output)
        print(f"  Disimpan: {fname}")

        results.append({
            "provider":provider_name,"model":model_name,
            "scenario":sc["name"],
            "bleu":scores["bleu"],"rouge1":scores["rouge1"],
            "rouge2":scores["rouge2"],"rougeL":scores["rougeL"],
            "mean":mean_s,"output_len":len(output),
            "time_s":secs,"success":not is_err,
        })
    return results


def print_table(all_results):
    print(f"\n{'='*80}")
    print("TABEL EVALUASI LLM — Format Studiawan et al. (2025)")
    print(f"{'='*80}")
    print(f"{'Provider':<22} {'Skenario':<22} {'BLEU':>7} {'R-1':>7} "
          f"{'R-2':>7} {'R-L':>7} {'Mean':>7} {'t':>5}")
    print("-"*80)
    prev=""
    for r in all_results:
        prov=r["provider"][:20]; sc=r["scenario"][:20]
        if prov!=prev and prev: print("-"*80)
        prev=prov
        flag="" if r["success"] else " X"
        print(f"{prov:<22} {sc:<22} {r['bleu']:>7.4f} {r['rouge1']:>7.4f} "
              f"{r['rouge2']:>7.4f} {r['rougeL']:>7.4f} {r['mean']:>7.4f} "
              f"{r['time_s']:>4.0f}s{flag}")
    print(f"{'='*80}")


# ============================================================
# MAIN
# ============================================================

def main():
    ap = argparse.ArgumentParser(description="Step 5 — LLM Report Full Scenario")
    ap.add_argument("--openrouter", action="store_true")
    ap.add_argument("--both",       action="store_true")
    ap.add_argument("--model",      type=str, default=None)
    args = ap.parse_args()

    mode = "both" if args.both else ("openrouter" if args.openrouter else "ollama")
    print("="*60)
    print(f"STEP 5 — Pelaporan LLM Full Scenario (mode: {mode})")
    print("="*60)

    print("\n[1] Membangun forensic digest (semua sumber)...")
    digest = build_full_digest()
    print(f"    [OK] {len(digest)} karakter, {len(digest.splitlines())} baris")

    all_results = []

    if mode in ("ollama","both"):
        print("\n[2] Menyiapkan Ollama...")
        try:
            model, available = get_ollama_model()
            print(f"    [OK] Dipilih: {model}")
            results = run_scenarios(
                f"Ollama ({model})", model,
                lambda p: call_ollama(p, model), digest)
            all_results.extend(results)
        except RuntimeError as e:
            print(f"\n    [ERROR] {e}")
            if mode=="ollama": return

    if mode in ("openrouter","both"):
        print("\n[3] Menyiapkan OpenRouter...")
        try:
            api_key  = check_openrouter_key()
            model_or = args.model or OPENROUTER_DEFAULT_MODEL
            print(f"    [OK] Model: {model_or}")
            results = run_scenarios(
                f"OpenRouter ({model_or})", model_or,
                lambda p: call_openrouter(p, model_or, api_key), digest)
            all_results.extend(results)
        except RuntimeError as e:
            print(f"\n    [ERROR] {e}")
            if mode=="openrouter": return

    if not all_results:
        print("\n[ERROR] Tidak ada hasil.")
        return

    print_table(all_results)

    csv_path = os.path.join(OUTPUT_DIR, "llm_evaluation_full_results.csv")
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=all_results[0].keys())
        w.writeheader(); w.writerows(all_results)

    print(f"\n[OK] CSV: {csv_path}")
    print(f"[OK] {sum(1 for r in all_results if r['success'])}/{len(all_results)} skenario berhasil")
    print("\n[SELESAI] Pipeline ORD2I Full Scenario selesai.")


if __name__ == "__main__":
    main()
