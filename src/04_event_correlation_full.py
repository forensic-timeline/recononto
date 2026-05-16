"""
==========================================================
STEP 4 — KORELASI EVENT (FULL SCENARIO 1)
==========================================================

FORMULA ORD2I (Chabot et al., 2015):
  Corr(e1,e2) = (CorrT + CorrS + CorrO) / 3  +  CorrEK

  CorrT: exp(-|Δt| / W)  — temporal decay, W=300s
  CorrS: kesamaan subjek (proses/user) — kontekstual
  CorrO: kesamaan objek (URL/path/domain)
  CorrEK: aturan pakar forensik (diperluas)

INPUT  : scenario1_all_events.csv
OUTPUT : hasil_sparql_full/correlation_full_results.csv
         hasil_sparql_full/correlation_full_report.txt
"""

import pandas as pd
import math
import csv
import os
import re
from datetime import datetime
from itertools import combinations

csv.field_size_limit(10 ** 7)

OUTPUT_DIR = "hasil_sparql_full"
os.makedirs(OUTPUT_DIR, exist_ok=True)

# ============================================================
# KONFIGURASI
# ============================================================

# Window temporal berbeda per kategori event
WINDOW_BROWSER    = 300   # 5 menit untuk browser
WINDOW_EXECUTION  = 600   # 10 menit untuk eksekusi aplikasi
WINDOW_SYSTEM     = 900   # 15 menit untuk event sistem

CORRELATION_THRESHOLD = 0.4

# Event type yang dianalisis (exclude generik noise)
INCLUDE_TYPES = {
    "WebpageVisit", "WebSearch", "CookieAccess", "BookmarkOp",
    "FileDownload",
    "AppExecution", "AppLaunch", "AppInstall",
    "UserLogon", "ProcessCreate",
    "RegistryModify", "AutoRun",
}

# Kategori untuk CorrS
BROWSER_TYPES   = {"WebpageVisit","WebSearch","CookieAccess","BookmarkOp","FileDownload"}
EXECUTION_TYPES = {"AppExecution","AppLaunch","AppInstall"}
SYSTEM_TYPES    = {"UserLogon","ProcessCreate","RegistryModify","AutoRun","SystemEvent"}


# ============================================================
# CorrT
# ============================================================

def get_window(type1: str, type2: str) -> int:
    """Window temporal disesuaikan dengan kategori event."""
    both = {type1, type2}
    if both <= BROWSER_TYPES:
        return WINDOW_BROWSER
    elif both <= EXECUTION_TYPES:
        return WINDOW_EXECUTION
    else:
        return WINDOW_SYSTEM   # mixed atau sistem


def corrT(dt1: datetime, dt2: datetime, window: int) -> float:
    if dt1 is None or dt2 is None:
        return 0.0
    delta = abs((dt2 - dt1).total_seconds())
    return math.exp(-delta / window)


# ============================================================
# CorrS
# ============================================================

def corrS(type1: str, type2: str) -> float:
    """
    Kesamaan subjek berdasarkan kategori event.
    - Dua event dalam kategori yang sama → CorrS tinggi
    - Kategori berbeda tapi terkait → CorrS sedang
    - Tidak terkait → CorrS rendah
    """
    cat1 = _category(type1)
    cat2 = _category(type2)

    if cat1 == cat2:
        return 1.0
    # Browser + Execution (download/install Firefox adalah awal dari browsing)
    if {cat1, cat2} == {"browser", "execution"}:
        return 0.7
    # Execution + System (install → registry change adalah wajar)
    if {cat1, cat2} == {"execution", "system"}:
        return 0.6
    # Browser + System (jarang tapi mungkin)
    if {cat1, cat2} == {"browser", "system"}:
        return 0.4
    return 0.3


def _category(evt_type: str) -> str:
    if evt_type in BROWSER_TYPES:   return "browser"
    if evt_type in EXECUTION_TYPES: return "execution"
    if evt_type in SYSTEM_TYPES:    return "system"
    return "other"


# ============================================================
# CorrO
# ============================================================

def corrO(row1: pd.Series, row2: pd.Series) -> float:
    """
    Kesamaan objek diperluas untuk semua tipe event.
    """
    type1 = str(row1.get("event_type",""))
    type2 = str(row2.get("event_type",""))

    # ── Browser: gunakan URL ──────────────────────────────
    if type1 in BROWSER_TYPES and type2 in BROWSER_TYPES:
        url1 = str(row1.get("url","")).strip()
        url2 = str(row2.get("url","")).strip()
        if not url1 or not url2:
            return 0.0
        if url1 == url2:
            return 1.0
        dom1 = _domain(url1)
        dom2 = _domain(url2)
        if dom1 and dom2 and dom1 == dom2:
            return 0.6
        return 0.0

    # ── Execution: gunakan app_name atau file_path ────────
    if type1 in EXECUTION_TYPES and type2 in EXECUTION_TYPES:
        app1 = str(row1.get("app_name","")).lower().strip()
        app2 = str(row2.get("app_name","")).lower().strip()
        fp1  = str(row1.get("file_path","")).lower()
        fp2  = str(row2.get("file_path","")).lower()
        if app1 and app2 and app1 == app2:
            return 1.0
        if app1 and app1 in fp2:
            return 0.7
        if app2 and app2 in fp1:
            return 0.7
        # Cek kesamaan direktori parent
        dir1 = _parent_dir(fp1)
        dir2 = _parent_dir(fp2)
        if dir1 and dir2 and dir1 == dir2:
            return 0.5
        return 0.0

    # ── Mixed: browser + execution ────────────────────────
    if (type1 in BROWSER_TYPES and type2 in EXECUTION_TYPES) or \
       (type2 in BROWSER_TYPES and type1 in EXECUTION_TYPES):
        url = str(row1.get("url","") or row2.get("url","")).lower()
        app = str(row1.get("app_name","") or row2.get("app_name","")).lower()
        fp  = str(row1.get("file_path","") or row2.get("file_path","")).lower()
        # Firefox browser + Firefox download/install
        if "firefox" in url and "firefox" in (app + fp):
            return 0.8
        if "mozilla" in url and "firefox" in (app + fp):
            return 0.7
        return 0.0

    return 0.0


def _domain(url: str) -> str:
    m = re.search(r'https?://([^/]+)', url)
    if m:
        h = m.group(1)
        parts = h.split(".")
        return ".".join(parts[-2:]) if len(parts) >= 2 else h
    return ""


def _parent_dir(path: str) -> str:
    if not path:
        return ""
    path = path.replace("\\", "/")
    parts = path.rstrip("/").rsplit("/", 1)
    return parts[0] if len(parts) > 1 else ""


# ============================================================
# CorrEK — Aturan Pakar (diperluas)
# ============================================================

def corrEK(row1: pd.Series, row2: pd.Series) -> float:
    """
    Aturan pakar forensik yang diperluas untuk full scenario.

    Browser rules:
    1. WebSearch → WebpageVisit (kausal, non-Google)
    2. WebpageVisit mozilla.org → AppLaunch Firefox
    3. FileDownload Firefox → AppInstall Firefox
    4. AppInstall Firefox → AppLaunch Firefox

    Execution rules:
    5. FileDownload → AppExecution (install dijalankan setelah download)
    6. AppInstall → AppLaunch (aplikasi dijalankan setelah install)

    System rules:
    7. UserLogon → AppExecution (pertama kali masuk → jalankan app)
    8. AutoRun → AppExecution (autorun → eksekusi)
    """
    t1   = str(row1.get("event_type",""))
    t2   = str(row2.get("event_type",""))
    url1 = str(row1.get("url","")).lower()
    url2 = str(row2.get("url","")).lower()
    app1 = str(row1.get("app_name","")).lower()
    app2 = str(row2.get("app_name","")).lower()
    fp1  = str(row1.get("file_path","")).lower()
    fp2  = str(row2.get("file_path","")).lower()
    msg1 = str(row1.get("message","")).lower()
    msg2 = str(row2.get("message","")).lower()

    # Rule 1: WebSearch → WebpageVisit (kausal utama)
    if t1 == "WebSearch" and t2 == "WebpageVisit":
        if "w3schools" in url2 and "sql" in url1:
            return 1.0
        if "w3schools" in url2:
            return 0.9
        if _domain(url2) not in ("google.com","bing.com","yahoo.com","duckduckgo.com"):
            return 0.6
        return 0.0

    # Rule 2: WebpageVisit mozilla.org → AppLaunch Firefox
    if t1 == "WebpageVisit" and t2 in ("AppLaunch","AppExecution"):
        if "mozilla" in url1 and "firefox" in (app2+fp2):
            return 0.9
        return 0.0
    if t2 == "WebpageVisit" and t1 in ("AppLaunch","AppExecution"):
        if "mozilla" in url2 and "firefox" in (app1+fp1):
            return 0.9
        return 0.0

    # Rule 3: FileDownload Firefox → AppInstall/AppExecution
    if t1 == "FileDownload" and t2 in ("AppInstall","AppExecution","AppLaunch"):
        if "firefox" in (url1+fp1) and "firefox" in (app2+fp2+msg2):
            return 0.9
        if "mozilla" in url1 and "firefox" in (app2+fp2+msg2):
            return 0.85
        return 0.0

    # Rule 4: AppInstall → AppLaunch (install → first run)
    if t1 == "AppInstall" and t2 == "AppLaunch":
        if app1 and app1 in (app2+fp2):
            return 0.8
        return 0.3

    # Rule 5: AppLaunch → WebpageVisit (browser launch → page visit)
    if t1 == "AppLaunch" and t2 == "WebpageVisit":
        if "firefox" in (app1+fp1):
            return 0.7
        return 0.0

    # Rule 6: UserLogon → AppExecution
    if t1 == "UserLogon" and t2 in ("AppExecution","AppLaunch"):
        return 0.5

    # Rule 7: AutoRun → AppExecution
    if t1 == "AutoRun" and t2 in ("AppExecution","AppLaunch"):
        return 0.6

    # Rule 8: WebSearch → CookieAccess (search menghasilkan cookie)
    if t1 == "WebSearch" and t2 == "CookieAccess":
        dom_search = _domain(url1)
        msg2_low   = msg2.lower()
        if dom_search and dom_search in msg2_low:
            return 0.7
        return 0.0

    return 0.0


# ============================================================
# DEDUPLICATION
# ============================================================

def deduplicate(df: pd.DataFrame) -> pd.DataFrame:
    """
    Hapus duplikat Plaso WAL dan self-duplicates.
    Strategi: keep first per (event_type + normalized_key + time_minute)
    """
    def norm_key(row):
        url  = str(row.get("url","")).strip().rstrip("/")
        app  = str(row.get("app_name","")).lower().strip()
        fp   = str(row.get("file_path","")).lower()
        url  = re.sub(r'^http://(www\.)?','https://www.', url)
        return url or app or fp[:80]

    df["_nkey"] = df.apply(norm_key, axis=1)
    df["_tmin"] = df["datetime"].astype(str).str[:16]
    df["_dk"]   = df["event_type"] + "|" + df["_nkey"] + "|" + df["_tmin"]

    before = len(df)
    df = df.drop_duplicates(subset=["_dk"]).reset_index(drop=True)
    after  = len(df)
    print(f"  Deduplication: {before} → {after} ({before-after} duplikat dihapus)")
    return df.drop(columns=["_nkey","_tmin","_dk"])


# ============================================================
# MAIN
# ============================================================

def main():
    print("=" * 60)
    print("STEP 4 — Korelasi Event (Full Scenario 1)")
    print("=" * 60)

    try:
        df = pd.read_csv("scenario1_all_events.csv", dtype=str)
    except FileNotFoundError:
        print("[ERROR] scenario1_all_events.csv tidak ditemukan.")
        sys.exit(1)

    for col in ["url","host","app_name","file_path","registry_key",
                "event_type","message","display_name"]:
        if col in df.columns:
            df[col] = df[col].fillna("").astype(str).replace("nan","")
        else:
            df[col] = ""

    # Filter event yang relevan
    df_analysis = df[df["event_type"].isin(INCLUDE_TYPES)].copy()
    print(f"\n[INFO] Event sebelum filter: {len(df):,}")
    print(f"[INFO] Event yang dianalisis ({', '.join(sorted(INCLUDE_TYPES))}): {len(df_analysis):,}")

    # Distribusi
    print("\n  Distribusi per event type:")
    for et, n in df_analysis["event_type"].value_counts().items():
        print(f"    {n:5d}  {et}")

    # Filter hanya yang punya konten bermakna
    def has_content(row):
        return any([
            row.get("url","").strip(),
            row.get("app_name","").strip(),
            row.get("file_path","").strip(),
            row.get("registry_key","").strip(),
            row.get("message","").strip(),
        ])
    df_analysis = df_analysis[df_analysis.apply(has_content, axis=1)].copy()
    print(f"\n[INFO] Setelah filter konten bermakna: {len(df_analysis):,}")

    # Deduplication
    df_analysis = deduplicate(df_analysis)
    print(f"[INFO] Setelah deduplication: {len(df_analysis):,}")

    # Parse timestamps
    def parse_dt(ts):
        try:
            return datetime.fromisoformat(str(ts).strip())
        except Exception:
            return None

    df_analysis["dt_parsed"] = df_analysis["datetime"].apply(parse_dt)
    df_analysis = df_analysis[df_analysis["dt_parsed"].notna()].reset_index(drop=True)
    print(f"[INFO] Event dengan timestamp valid: {len(df_analysis):,}")

    if len(df_analysis) < 2:
        print("[WARN] Terlalu sedikit event untuk dianalisis.")
        return

    # ── Hitung korelasi ─────────────────────────────────
    print(f"\n[INFO] Menghitung korelasi... ({len(df_analysis)} events)")
    print(f"       Estimasi pasangan C(n,2) = {len(df_analysis)*(len(df_analysis)-1)//2:,}")

    results   = []
    skipped   = 0
    processed = 0

    for i, j in combinations(range(len(df_analysis)), 2):
        row1 = df_analysis.iloc[i]
        row2 = df_analysis.iloc[j]

        dt1 = row1["dt_parsed"]
        dt2 = row2["dt_parsed"]

        t1  = str(row1.get("event_type",""))
        t2  = str(row2.get("event_type",""))

        # Window adaptif
        window = get_window(t1, t2)
        delta  = abs((dt2 - dt1).total_seconds())

        # Skip jika di luar window × 2
        if delta > window * 2:
            skipped += 1
            continue

        processed += 1

        ct  = corrT(dt1, dt2, window)
        cs  = corrS(t1, t2)
        co  = corrO(row1, row2)
        ek  = corrEK(row1, row2)

        base_score  = (ct + cs + co) / 3.0
        final_score = max(base_score, ek) if ek > 0 else base_score

        if final_score >= CORRELATION_THRESHOLD:
            results.append({
                "event1_id":   str(i),
                "event2_id":   str(j),
                "event1_time": str(row1.get("datetime","")),
                "event2_time": str(row2.get("datetime","")),
                "event1_type": t1,
                "event2_type": t2,
                "event1_url":  str(row1.get("url",""))[:80],
                "event2_url":  str(row2.get("url",""))[:80],
                "event1_app":  str(row1.get("app_name",""))[:60],
                "event2_app":  str(row2.get("app_name",""))[:60],
                "event1_path": str(row1.get("file_path",""))[:80],
                "event2_path": str(row2.get("file_path",""))[:80],
                "CorrT":       round(ct, 3),
                "CorrS":       round(cs, 3),
                "CorrO":       round(co, 3),
                "CorrEK":      round(ek, 3),
                "score":       round(final_score, 3),
                "window_s":    window,
                "delta_s":     round(delta, 1),
            })

    print(f"\n[INFO] Pasangan dalam window: {processed:,}")
    print(f"[INFO] Pasangan di atas threshold ({CORRELATION_THRESHOLD}): {len(results):,}")
    print(f"[INFO] Pasangan dilewati (di luar window): {skipped:,}")

    if not results:
        print("[WARN] Tidak ada pasangan berkorelasi.")
        return

    # Simpan CSV
    df_res = pd.DataFrame(results).sort_values("score", ascending=False)
    out_csv = os.path.join(OUTPUT_DIR, "correlation_full_results.csv")
    df_res.to_csv(out_csv, index=False)
    print(f"\n[OK] CSV: {out_csv}")

    # ── Tampilkan hasil ──────────────────────────────────
    print("\n" + "="*70)
    print("TOP 15 PASANGAN EVENT BERKORELASI")
    print("="*70)
    print(f"{'Skor':>6} | {'T':>5} | {'S':>5} | {'O':>5} | {'EK':>5} | Tipe Pasangan")
    print("-"*70)

    seen_pairs = set()
    shown = 0
    for _, r in df_res.iterrows():
        key = (r["event1_type"], r["event1_url"][:30],
               r["event2_type"], r["event2_url"][:30])
        if key in seen_pairs:
            continue
        seen_pairs.add(key)
        print(f"  {r['score']:>5.3f} | {r['CorrT']:>5.3f} | {r['CorrS']:>5.3f} | "
              f"{r['CorrO']:>5.3f} | {r['CorrEK']:>5.3f} | "
              f"{r['event1_type']} → {r['event2_type']}")
        info1 = r['event1_url'] or r['event1_app'] or r['event1_path']
        info2 = r['event2_url'] or r['event2_app'] or r['event2_path']
        if info1:
            print(f"         [{str(r['event1_time'])[:19]}] {info1[:60]}")
        if info2:
            print(f"         [{str(r['event2_time'])[:19]}] {info2[:60]}")
        shown += 1
        if shown >= 15:
            break

    # ── Buat laporan teks ────────────────────────────────
    report_lines = [
        "=== LAPORAN KORELASI EVENT — FULL SCENARIO 1 ===",
        f"Dataset : Zenodo Scenario 1 (Studiawan et al., 2025)",
        f"Formula : Corr(e1,e2) = (CorrT + CorrS + CorrO) / 3 + CorrEK",
        f"Window  : Browser={WINDOW_BROWSER}s | Execution={WINDOW_EXECUTION}s | System={WINDOW_SYSTEM}s",
        f"Threshold: {CORRELATION_THRESHOLD}",
        f"Event dianalisis: {len(df_analysis)}",
        f"Pasangan berkorelasi: {len(results)}",
        "",
        "=== RANTAI KEJADIAN UTAMA ===",
    ]

    seen2 = set()
    for _, r in df_res[df_res["score"] >= 0.6].iterrows():
        t1 = str(r["event1_time"])[:19]
        t2 = str(r["event2_time"])[:19]
        u1 = r["event1_url"] or r["event1_app"] or r["event1_path"]
        u2 = r["event2_url"] or r["event2_app"] or r["event2_path"]
        key = (r["event1_type"], u1[:40], r["event2_type"], u2[:40])
        if key in seen2: continue
        seen2.add(key)
        report_lines.append(
            f"[{t1}] {r['event1_type']}: {u1[:55]}")
        report_lines.append(
            f"  ──(score={r['score']:.3f} | Δt={r['delta_s']}s)──▶")
        report_lines.append(
            f"[{t2}] {r['event2_type']}: {u2[:55]}")
        report_lines.append("")

    report_path = os.path.join(OUTPUT_DIR, "correlation_full_report.txt")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write("\n".join(report_lines))
    print(f"\n[OK] Laporan: {report_path}")
    print(f"\n[SELESAI] Lanjutkan ke Step 5: python3 05_llm_report_full.py")


if __name__ == "__main__":
    import sys
    main()
