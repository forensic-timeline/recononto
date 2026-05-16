"""
==========================================================
STEP 1 — PREPROCESSING FULL SCENARIO 1 (SEMUA ARTEFAK)
==========================================================

TUJUAN:
  Mengklasifikasikan SELURUH 31.878 event dari all_events.csv
  ke dalam tipe event forensik yang bermakna untuk ORD2I.
  Tidak lagi terbatas pada Firefox saja — semua artefak
  Windows 11 diproses: browser, filesystem, registry,
  event log, prefetch, LNK, dll.


TIPE EVENT YANG DIHASILKAN:
  Browser   : WebpageVisit, WebSearch, CookieAccess,
              BookmarkOp, FileDownload
  Sistem    : AppExecution, AppLaunch, AppInstall
  File      : FileCreate, FileModify, FileDelete, FileAccess
  Registry  : RegistryModify, AutoRun
  System    : UserLogon, ProcessCreate, SystemEvent
  Lain-lain : TaskSchedule, ServiceModify, FileSystemOp

INPUT  : all_events.csv
OUTPUT : scenario1_all_events.csv

JALANKAN:
  pip install pandas
  python3 01_preprocess_all.py
"""

import csv
import re
import sys
import os
import pandas as pd
from datetime import datetime

csv.field_size_limit(10 ** 7)

INPUT_FILE  = "all_events.csv"
OUTPUT_FILE = "scenario1_all_events.csv"

# ============================================================
# MAPPING PARSER → KATEGORI SUMBER
# ============================================================

BROWSER_PARSERS = {
    "sqlite/firefox_history",
    "sqlite/firefox_10_cookies",
    "sqlite/firefox_27_cookies",
    "sqlite/firefox_bookmark_folder",
    "sqlite/firefox_downloads",
    "sqlite/chrome_27_history",
    "sqlite/chrome_8_history",
    "sqlite/chrome_66_cookies",
    "sqlite/chrome_cache",
    "chrome_cache",
}

REGISTRY_PARSERS = {
    "winreg/winreg_default",
    "winreg/amcache",
    "winreg/userassist",
    "winreg/bam",
    "winreg/windows_services",
    "winreg/windows_task_cache",
    "winreg/appcompatcache",
    "winreg/mrulist",
    "winreg/run",
    "winreg/shimcache",
    "winreg/muicache",
    "winreg/typedurls",
    "winreg/terminal_server_client",
    "winreg/mstsc_rdp",
    "winreg/winrar",
}

EXECUTION_PARSERS = {
    "prefetch",
    "prefetch/prefetch",
    "winreg/amcache",
    "winreg/bam",
    "winreg/userassist",
    "winreg/appcompatcache",
}

LNK_PARSERS = {
    "lnk",
    "lnk/shell_items",
    "custom_destinations/lnk",
    "custom_destinations/lnk/shell_items",
    "olecf/olecf_default",
}

EVTX_PARSERS = {
    "winevtx",
    "winjob",
}


# ============================================================
# FUNGSI KLASIFIKASI EVENT TYPE
# ============================================================

def classify_event(row: dict) -> str:
    """
    Mengklasifikasikan event ke tipe ORD2I berdasarkan parser,
    message, dan source. Mencakup seluruh artefak Windows 11.

    Urutan prioritas:
    1. Browser-specific parsers (paling spesifik)
    2. Execution parsers (prefetch, amcache, BAM)
    3. Registry parsers
    4. LNK/Shortcut parsers
    5. Event log parsers
    6. Filesystem (filestat, usnjrnl) — paling generik
    """
    parser  = str(row.get("parser",       "")).lower().strip()
    message = str(row.get("message",      "")).strip()
    source  = str(row.get("source",       "")).upper().strip()
    display = str(row.get("display_name", "")).lower().strip()
    msg_lo  = message.lower()

    # ── 1. BROWSER ─────────────────────────────────────────
    if "firefox_history" in parser or "chrome_27_history" in parser \
       or "chrome_8_history" in parser:
        # Search: URL mengandung query string mesin pencari
        if any(se in msg_lo for se in [
            "google.com/search", "bing.com/search",
            "search?q=", "?q=", "search?query=",
        ]):
            return "WebSearch"
        # Bookmark: message kosong atau nama folder bookmark
        bookmark_names = {"menu","tags","toolbar","unfiled","mobile","nan",""}
        if message.strip().lower() in bookmark_names or not message.strip():
            return "BookmarkOp"
        # Kunjungan halaman
        if msg_lo.startswith("http"):
            return "WebpageVisit"
        return "WebpageVisit"

    if "cookie" in parser:
        return "CookieAccess"

    if "firefox_bookmark" in parser:
        return "BookmarkOp"

    if "firefox_download" in parser:
        return "FileDownload"

    if "chrome_cache" in parser or parser == "chrome_cache":
        # Cache bisa berisi URL — tetap FileDownload/CacheAccess
        if "original url:" in msg_lo or msg_lo.startswith("http"):
            return "FileDownload"
        return "FileSystemOp"

    # ── 2. EXECUTION ───────────────────────────────────────
    if parser == "prefetch" or parser == "prefetch/prefetch":
        return "AppExecution"

    if parser == "winreg/amcache":
        return "AppInstall"

    if parser == "winreg/bam":
        return "AppExecution"

    if parser == "winreg/userassist":
        return "AppLaunch"

    if parser == "winreg/appcompatcache" or parser == "winreg/shimcache":
        return "AppExecution"

    # ── 3. REGISTRY ────────────────────────────────────────
    if parser == "winreg/run" or parser == "winreg/runonce":
        return "AutoRun"

    if parser == "winreg/windows_services":
        return "ServiceModify"

    if parser == "winreg/windows_task_cache" or parser == "winjob":
        return "TaskSchedule"

    if parser in ("winreg/mrulist", "winreg/typedurls",
                  "winreg/terminal_server_client", "winreg/mstsc_rdp",
                  "winreg/muicache", "winreg/winrar"):
        return "FileAccess"

    if parser.startswith("winreg/"):
        return "RegistryModify"

    # ── 4. LNK / SHORTCUT ──────────────────────────────────
    if parser in ("lnk", "lnk/shell_items",
                  "custom_destinations/lnk",
                  "custom_destinations/lnk/shell_items"):
        # LNK yang mengarah ke executable → AppLaunch
        if any(ext in display for ext in [".exe", ".bat", ".cmd", ".msi"]):
            return "AppLaunch"
        return "FileAccess"

    if "olecf" in parser:
        return "FileAccess"

    # ── 5. EVENT LOG ───────────────────────────────────────
    if parser == "winevtx":
        # Logon/Logoff events
        if any(k in msg_lo for k in [
            "logon", "logoff", "log on", "log off", "session opened",
            "account was successfully logged",
        ]):
            return "UserLogon"
        # Process creation
        if any(k in msg_lo for k in [
            "process creation", "new process", "process has exited",
            "a new process has been created",
        ]):
            return "ProcessCreate"
        # Service events
        if any(k in msg_lo for k in ["service", "driver"]):
            return "ServiceModify"
        return "SystemEvent"

    if parser == "winpca_dic":
        return "AppExecution"

    # ── 6. FILESYSTEM ──────────────────────────────────────
    if parser == "usnjrnl":
        # USN Journal: bisa create, modify, delete, rename
        if any(k in msg_lo for k in ["file_create", "data_extend",
                                      "file created", "$i30"]):
            return "FileCreate"
        if any(k in msg_lo for k in ["file_delete", "close", "deleted"]):
            return "FileDelete"
        # Firefox/browser executable → AppLaunch
        if any(k in display for k in [
            "firefox.exe", "firefox installer", "msedge.exe",
            "chrome.exe", ".msi", "setup.exe", "install",
        ]):
            return "AppLaunch"
        return "FileModify"

    if parser == "filestat":
        # Filestat: metadata file dari NTFS
        # Deteksi executable yang dijalankan
        if any(k in display for k in [
            "firefox.exe", "firefox installer", "msedge.exe",
            "chrome.exe", "setup.exe", ".msi",
        ]):
            return "AppLaunch"
        # Download Firefox
        if "firefox installer" in display or "firefox setup" in display:
            return "FileDownload"
        # Deteksi dari message
        if "firefox.exe" in msg_lo or "mozilla firefox" in msg_lo:
            return "AppLaunch"
        return "FileSystemOp"

    # ── DEFAULT ────────────────────────────────────────────
    return "FileSystemOp"


# ============================================================
# FUNGSI EKSTRAKSI KOLOM TAMBAHAN
# ============================================================

def extract_url(message: str) -> str:
    """Ekstrak URL dari message berbagai format Plaso."""
    if not message:
        return ""
    # Format browser history: URL di awal baris
    m = re.match(r'^(https?://[^\s\[(<]+)', message.strip())
    if m:
        return m.group(1).rstrip("/ ")
    # Format "Original URL: ..."
    m = re.search(r'[Oo]riginal [Uu][Rr][Ll]:\s*(https?://\S+)', message)
    if m:
        return m.group(1).rstrip("/ ")
    # Format "Destination: URL"
    m = re.search(r'[Dd]estination:\s*(https?://\S+)', message)
    if m:
        return m.group(1).rstrip("/ ")
    return ""


def extract_host(message: str, url: str) -> str:
    """Ekstrak hostname dari message atau URL."""
    if not message:
        return ""
    # Firefox format: "Host: google.com"
    m = re.search(r'[Hh]ost:\s*([^\s,;]+)', message)
    if m:
        return m.group(1)
    # Dari URL
    if url:
        m = re.search(r'https?://([^/]+)', url)
        if m:
            return m.group(1)
    return ""


def extract_title(message: str) -> str:
    """Ekstrak judul halaman dari message Chrome/Firefox format."""
    if not message:
        return ""
    # Chrome: "(Page Title) [count:"
    m = re.search(r'\(([^)]{3,120})\)\s*\[count:', message)
    if m:
        t = m.group(1).strip()
        if "not typed" not in t.lower():
            return t
    return ""


def extract_app_name(message: str, display: str) -> str:
    """Ekstrak nama aplikasi dari prefetch/LNK/registry message."""
    if not message and not display:
        return ""
    # Prefetch: "Name: FIREFOX.EXE"
    m = re.search(r'[Nn]ame:\s*([^\s,]+\.exe)', message or "")
    if m:
        return m.group(1)
    # LNK: ambil basename dari path
    m = re.search(r'\\([^\\]+\.(?:exe|msi|bat|cmd))', display or "", re.IGNORECASE)
    if m:
        return m.group(1)
    # Dari message path
    m = re.search(r'\\([^\\]+\.(?:exe|msi|bat|cmd))', message or "", re.IGNORECASE)
    if m:
        return m.group(1)
    return ""


def extract_registry_key(message: str, display: str) -> str:
    """Ekstrak registry key path dari message."""
    if not message:
        return ""
    # Format: "HKEY_..." atau "HKLM\..." atau "HKCU\..."
    m = re.search(r'(HK[A-Z_]+(?:\\[^,\n]+)+)', message)
    if m:
        return m.group(1)[:200]
    # Dari display_name
    if display and ("HKEY" in display.upper() or "HKLM" in display.upper()):
        return display[:200]
    return ""


def extract_file_path(display: str, message: str) -> str:
    """Ekstrak path file dari display_name atau message."""
    if display and display.strip():
        # Hapus prefix NTFS:
        p = re.sub(r'^NTFS:', '', display.strip())
        return p[:300]
    if message:
        m = re.search(r'([A-Za-z]:\\[^\s\[<>|"]+)', message)
        if m:
            return m.group(1)[:300]
    return ""


def normalize_timestamp(ts: str) -> str:
    """Normalisasi timestamp ke ISO 8601."""
    if not ts or str(ts).strip() in ("", "nan", "None"):
        return ""
    return str(ts).strip()


# ============================================================
# MAIN
# ============================================================

def main():
    print("=" * 60)
    print("STEP 1 — Preprocessing Full Scenario 1")
    print("         (Semua Artefak, bukan hanya Firefox)")
    print("=" * 60)

    if not os.path.exists(INPUT_FILE):
        print(f"\n[ERROR] File '{INPUT_FILE}' tidak ditemukan!")
        print("Pastikan all_events.csv (output Plaso) ada di direktori ini.")
        sys.exit(1)

    print(f"\n[1/4] Membaca {INPUT_FILE}...")
    df = pd.read_csv(INPUT_FILE, dtype=str)
    df = df.fillna("")
    print(f"      Total event: {len(df):,}")
    print(f"      Kolom: {list(df.columns)}")

    # Pastikan kolom wajib ada
    required = ["datetime", "message", "parser"]
    missing = [c for c in required if c not in df.columns]
    if missing:
        print(f"\n[ERROR] Kolom tidak ditemukan: {missing}")
        print("Pastikan file adalah output Plaso dengan kolom standar.")
        sys.exit(1)

    # Kolom opsional dengan fallback
    for col in ["source", "display_name", "timestamp_desc"]:
        if col not in df.columns:
            df[col] = ""

    print("\n[2/4] Mengklasifikasikan event type...")
    df["event_type"] = df.apply(classify_event, axis=1)

    print("\n[3/4] Mengekstrak kolom tambahan...")
    df["url"]           = df["message"].apply(extract_url)
    df["host"]          = df.apply(lambda r: extract_host(r["message"], r["url"]), axis=1)
    df["page_title"]    = df["message"].apply(extract_title)
    df["app_name"]      = df.apply(lambda r: extract_app_name(r["message"], r.get("display_name","")), axis=1)
    df["registry_key"]  = df.apply(lambda r: extract_registry_key(r["message"], r.get("display_name","")), axis=1)
    df["file_path"]     = df.apply(lambda r: extract_file_path(r.get("display_name",""), r["message"]), axis=1)
    df["timestamp_clean"] = df["datetime"].apply(normalize_timestamp)

    # Urutkan berdasarkan waktu
    df = df.sort_values("datetime").reset_index(drop=True)

    # Pilih kolom output
    out_cols = [
        "datetime", "timestamp_clean", "timestamp_desc",
        "event_type", "source", "parser",
        "url", "host", "page_title",
        "app_name", "registry_key", "file_path",
        "message", "display_name",
    ]
    out_cols = [c for c in out_cols if c in df.columns]
    df_out = df[out_cols]

    print(f"\n[4/4] Menyimpan ke {OUTPUT_FILE}...")
    df_out.to_csv(OUTPUT_FILE, index=False, encoding="utf-8")
    print(f"      [OK] {len(df_out):,} event disimpan")

    # ── Statistik ─────────────────────────────────────────
    print("\n" + "=" * 60)
    print("STATISTIK DISTRIBUSI EVENT TYPE")
    print("=" * 60)

    et_counts = df["event_type"].value_counts()
    total = len(df)
    for et, n in et_counts.items():
        bar = "█" * int(n / total * 40)
        print(f"  {n:6,} ({n/total*100:5.1f}%)  {et:<18}  {bar}")

    print(f"\n  Total: {total:,} events")

    print("\n" + "=" * 60)
    print("DISTRIBUSI SOURCE")
    print("=" * 60)
    for s, n in df["source"].value_counts().items():
        print(f"  {n:6,}  {s}")

    print("\n" + "=" * 60)
    print("TOP PARSER")
    print("=" * 60)
    for p, n in df["parser"].value_counts().head(20).items():
        print(f"  {n:6,}  {p}")

    # Sampel per event type penting
    for et in ["WebSearch", "WebpageVisit", "AppExecution", "UserLogon"]:
        subset = df[df["event_type"] == et]
        if not subset.empty:
            print(f"\n--- Contoh {et} ({len(subset)} events) ---")
            for _, r in subset.head(3).iterrows():
                ts  = str(r["datetime"])[:19]
                msg = str(r["message"])[:80]
                print(f"  [{ts}] {msg}")

    print(f"\n[SELESAI] Output: {OUTPUT_FILE}")
    print(f"          Lanjutkan ke Step 2: python3 02_build_ord2i_full.py")


if __name__ == "__main__":
    main()
