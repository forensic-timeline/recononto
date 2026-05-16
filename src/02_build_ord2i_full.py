"""
==========================================================
STEP 2 — INSTANSIASI ONTOLOGI ORD2I (FULL SCENARIO 1)
==========================================================

TUJUAN:
  Menginstansiasi ontologi ORD2I untuk SELURUH event
  dari Scenario 1 — bukan hanya browser Firefox.

INPUT  : scenario1_all_events.csv
OUTPUT : scenario1_ord2i_full.ttl

JALANKAN:
  pip install rdflib pandas
  python3 02_build_ord2i_full.py
"""

import pandas as pd
import csv
import sys
import re
from datetime import datetime
from rdflib import (
    Graph, Namespace, RDF, RDFS, OWL, XSD, Literal, URIRef
)

csv.field_size_limit(10 ** 7)

ORD2I = Namespace("http://example.org/ord2i#")
TIME  = Namespace("http://www.w3.org/2006/time#")
PROV  = Namespace("http://www.w3.org/ns/prov#")

INPUT_FILE  = "scenario1_all_events.csv"
OUTPUT_FILE = "scenario1_ord2i_full.ttl"

BATCH_SIZE  = 500   # Cetak progress setiap N event


# ============================================================
# HELPERS
# ============================================================

def safe_uri(text: str) -> str:
    text = str(text)
    text = re.sub(r'[^\w]', '_', text)
    text = re.sub(r'_+', '_', text)
    return text.strip('_')[:80]


def make_time_interval(g: Graph, dt_str: str, event_uri: URIRef):
    if not dt_str or dt_str in ("nan", "None", ""):
        return
    interval_uri = URIRef(str(event_uri) + "_interval")
    g.add((interval_uri, RDF.type, TIME.ProperInterval))
    g.add((interval_uri, TIME.hasBeginning, Literal(dt_str, datatype=XSD.dateTime)))
    g.add((interval_uri, TIME.hasEnd,       Literal(dt_str, datatype=XSD.dateTime)))
    g.add((event_uri, ORD2I.hasTimeInterval, interval_uri))


# ============================================================
# SCHEMA (TBox)
# ============================================================

def build_schema(g: Graph):
    print("[INFO] Membangun schema ORD2I (TBox)...")

    ont = URIRef("http://example.org/ord2i")
    g.add((ont, RDF.type,    OWL.Ontology))
    g.add((ont, RDFS.label,  Literal("ORD2I Full Scenario 1 — Zenodo")))
    g.add((ont, RDFS.comment,Literal("Implementasi ORD2I lengkap untuk seluruh artefak Windows 11. Chabot et al. (2015)")))

    # ── CKL Classes ────────────────────────────────────────
    for cls in [ORD2I.Entity, ORD2I.Event, ORD2I.Subject,
                ORD2I.Object, ORD2I.Location]:
        g.add((cls, RDF.type, OWL.Class))

    g.add((ORD2I.Event,   RDFS.subClassOf, ORD2I.Entity))
    g.add((ORD2I.Subject, RDFS.subClassOf, ORD2I.Entity))
    g.add((ORD2I.Object,  RDFS.subClassOf, ORD2I.Entity))

    # Subject subclasses
    g.add((ORD2I.Person,  RDFS.subClassOf, ORD2I.Subject))
    g.add((ORD2I.Process, RDFS.subClassOf, ORD2I.Subject))

    # Location subclasses
    g.add((ORD2I.VirtualLocation,       RDFS.subClassOf, ORD2I.Location))
    g.add((ORD2I.LocalVirtualLocation,  RDFS.subClassOf, ORD2I.VirtualLocation))
    g.add((ORD2I.RemoteVirtualLocation, RDFS.subClassOf, ORD2I.VirtualLocation))
    g.add((ORD2I.PhysicalLocation,      RDFS.subClassOf, ORD2I.Location))

    # ── CKL Properties ─────────────────────────────────────
    for prop in [ORD2I.hasEventType, ORD2I.hasStatus, ORD2I.hasParser,
                 ORD2I.hasSource, ORD2I.hasRawMessage, ORD2I.hasDescription]:
        g.add((prop, RDF.type, OWL.DatatypeProperty))

    for prop in [ORD2I.hasTimeInterval, ORD2I.isInvolved, ORD2I.undergoes,
                 ORD2I.uses, ORD2I.creates, ORD2I.modifies, ORD2I.removes,
                 ORD2I.hasLocation]:
        g.add((prop, RDF.type, OWL.ObjectProperty))

    # ── SKL — Browser ──────────────────────────────────────
    for cls in [ORD2I.WebObject, ORD2I.Webpage, ORD2I.WebResource,
                ORD2I.Cookie, ORD2I.Bookmark]:
        g.add((cls, RDF.type, OWL.Class))
    g.add((ORD2I.WebObject,   RDFS.subClassOf, ORD2I.Object))
    g.add((ORD2I.Webpage,     RDFS.subClassOf, ORD2I.WebObject))
    g.add((ORD2I.WebResource, RDFS.subClassOf, ORD2I.WebObject))
    g.add((ORD2I.Cookie,      RDFS.subClassOf, ORD2I.WebObject))
    g.add((ORD2I.Bookmark,    RDFS.subClassOf, ORD2I.WebObject))

    # SKL — File
    for cls in [ORD2I.File, ORD2I.ExeFile, ORD2I.DownloadedFile,
                ORD2I.ShortcutFile]:
        g.add((cls, RDF.type, OWL.Class))
    g.add((ORD2I.File,          RDFS.subClassOf, ORD2I.Object))
    g.add((ORD2I.ExeFile,       RDFS.subClassOf, ORD2I.File))
    g.add((ORD2I.DownloadedFile,RDFS.subClassOf, ORD2I.File))
    g.add((ORD2I.ShortcutFile,  RDFS.subClassOf, ORD2I.File))

    # SKL — System
    for cls in [ORD2I.RegistryKey, ORD2I.ProcessExecution,
                ORD2I.EventLogEntry, ORD2I.WindowsService,
                ORD2I.ScheduledTask, ORD2I.Account, ORD2I.WinUserAccount]:
        g.add((cls, RDF.type, OWL.Class))
    g.add((ORD2I.RegistryKey,     RDFS.subClassOf, ORD2I.Object))
    g.add((ORD2I.ProcessExecution,RDFS.subClassOf, ORD2I.Object))
    g.add((ORD2I.EventLogEntry,   RDFS.subClassOf, ORD2I.Object))
    g.add((ORD2I.WindowsService,  RDFS.subClassOf, ORD2I.Object))
    g.add((ORD2I.ScheduledTask,   RDFS.subClassOf, ORD2I.Object))
    g.add((ORD2I.Account,         RDFS.subClassOf, ORD2I.Object))
    g.add((ORD2I.WinUserAccount,  RDFS.subClassOf, ORD2I.Account))

    # ── SKL Properties ─────────────────────────────────────
    for prop in [
        ORD2I.hasURL, ORD2I.hasHostname, ORD2I.hasPageTitle,
        ORD2I.hasVisitCount, ORD2I.hasCookieName, ORD2I.hasCookieDomain,
        ORD2I.hasFilePath, ORD2I.hasUsername, ORD2I.hasAppName,
        ORD2I.hasRegistryKey, ORD2I.hasRegistryValue,
        ORD2I.hasProcessName, ORD2I.hasRunCount,
        ORD2I.hasEventID, ORD2I.hasEventChannel,
        ORD2I.hasServiceName, ORD2I.hasTaskName,
    ]:
        g.add((prop, RDF.type, OWL.DatatypeProperty))

    # ── TKL ────────────────────────────────────────────────
    for cls in [ORD2I.InvestigativeOperation, ORD2I.Tool,
                ORD2I.Investigator, ORD2I.Contribution, ORD2I.Organization]:
        g.add((cls, RDF.type, OWL.Class))

    for prop in [ORD2I.identifiedBy, ORD2I.isSupportedBy,
                 ORD2I.isPerformedWith, ORD2I.hasContribution]:
        g.add((prop, RDF.type, OWL.ObjectProperty))

    for prop in [ORD2I.hasTechnique, ORD2I.hasInfoSource, ORD2I.hasConfidence,
                 ORD2I.hasOperationDate, ORD2I.hasToolName,
                 ORD2I.hasToolVersion, ORD2I.hasInvestigatorName]:
        g.add((prop, RDF.type, OWL.DatatypeProperty))

    print("      [OK] Schema selesai (CKL + SKL extended + TKL)")


# ============================================================
# TKL INSTANCES
# ============================================================

def build_tkl(g: Graph) -> tuple:
    tool_uri = ORD2I.Tool_Plaso
    g.add((tool_uri, RDF.type,              ORD2I.Tool))
    g.add((tool_uri, ORD2I.hasToolName,     Literal("log2timeline/Plaso")))
    g.add((tool_uri, ORD2I.hasToolVersion,  Literal("20230717")))
    g.add((tool_uri, RDFS.label,            Literal("Plaso forensic timeline tool")))

    inv_uri = ORD2I.Investigator_Researcher
    g.add((inv_uri, RDF.type,                    ORD2I.Investigator))
    g.add((inv_uri, ORD2I.hasInvestigatorName,   Literal("Peneliti Tesis")))
    g.add((inv_uri, RDFS.label,                  Literal("Forensic Investigator — ITS")))

    op_uri = ORD2I.InvestigativeOp_FullScenario1
    g.add((op_uri, RDF.type,               ORD2I.InvestigativeOperation))
    g.add((op_uri, ORD2I.hasTechnique,     Literal("Full extraction of all Windows 11 artifacts via log2timeline/Plaso")))
    g.add((op_uri, ORD2I.hasInfoSource,    Literal("All Plaso parsers: browser SQLite, NTFS, registry, event log, prefetch, LNK")))
    g.add((op_uri, ORD2I.hasConfidence,    Literal(0.9, datatype=XSD.float)))
    g.add((op_uri, ORD2I.hasOperationDate, Literal(datetime.now().isoformat(), datatype=XSD.dateTime)))
    g.add((op_uri, ORD2I.isPerformedWith,  tool_uri))
    g.add((op_uri, RDFS.label,             Literal("Full Scenario 1 extraction — Zenodo")))

    contrib = ORD2I.Contribution_Full
    g.add((contrib, RDF.type,             ORD2I.Contribution))
    g.add((contrib, ORD2I.hasContribution, inv_uri))
    g.add((op_uri,  ORD2I.hasContribution, contrib))

    return op_uri, tool_uri, inv_uri


# ============================================================
# INSTANTIATE ONE EVENT (CKL + SKL)
# ============================================================

def instantiate_event(g, row, event_id, op_uri, user_uri, system_proc_uri):
    dt_str   = str(row.get("datetime",      "")).strip()
    evt_type = str(row.get("event_type",    "FileSystemOp")).strip()
    parser   = str(row.get("parser",        "")).strip()
    message  = str(row.get("message",       "")).strip()
    source   = str(row.get("source",        "")).strip()
    url      = str(row.get("url",           "")).strip()
    host     = str(row.get("host",          "")).strip()
    title    = str(row.get("page_title",    "")).strip()
    app_name = str(row.get("app_name",      "")).strip()
    reg_key  = str(row.get("registry_key",  "")).strip()
    file_path= str(row.get("file_path",     "")).strip()

    # ── CKL Event ──────────────────────────────────────────
    ev_uri = ORD2I[f"Event_{event_id:06d}"]
    g.add((ev_uri, RDF.type,            ORD2I.Event))
    g.add((ev_uri, ORD2I.hasEventType,  Literal(evt_type)))
    g.add((ev_uri, ORD2I.hasParser,     Literal(parser)))
    g.add((ev_uri, ORD2I.hasSource,     Literal(source)))
    g.add((ev_uri, ORD2I.hasStatus,     Literal("success")))
    if message:
        g.add((ev_uri, ORD2I.hasRawMessage, Literal(message[:400])))

    if dt_str and dt_str not in ("nan", "None", ""):
        make_time_interval(g, dt_str, ev_uri)

    # Hubungkan ke Subject
    g.add((user_uri,       ORD2I.isInvolved, ev_uri))
    g.add((system_proc_uri,ORD2I.isInvolved, ev_uri))

    # ── SKL Object — Browser ───────────────────────────────
    if evt_type == "WebpageVisit" and url:
        obj_uri = ORD2I[f"Webpage_{event_id:06d}"]
        g.add((obj_uri, RDF.type,           ORD2I.Webpage))
        g.add((obj_uri, ORD2I.hasURL,       Literal(url, datatype=XSD.anyURI)))
        g.add((obj_uri, ORD2I.hasHostname,  Literal(host)))
        if title:
            g.add((obj_uri, ORD2I.hasPageTitle, Literal(title)))
        loc = ORD2I[f"Loc_Remote_{event_id:06d}"]
        g.add((loc, RDF.type,    ORD2I.RemoteVirtualLocation))
        g.add((loc, ORD2I.hasURL, Literal(url, datatype=XSD.anyURI)))
        g.add((obj_uri, ORD2I.hasLocation, loc))
        g.add((ev_uri, ORD2I.uses, obj_uri))

    elif evt_type == "WebSearch" and url:
        obj_uri = ORD2I[f"WebResource_{event_id:06d}"]
        g.add((obj_uri, RDF.type,          ORD2I.WebResource))
        g.add((obj_uri, ORD2I.hasURL,      Literal(url, datatype=XSD.anyURI)))
        g.add((obj_uri, ORD2I.hasHostname, Literal(host)))
        m = re.search(r'[?&](?:q|oq|query)=([^&]+)', url)
        if m:
            query = m.group(1).replace('+', ' ').replace('%20', ' ')
            g.add((obj_uri, ORD2I.hasDescription,
                   Literal(f"Search query: {query}")))
        g.add((ev_uri, ORD2I.uses, obj_uri))

    elif evt_type == "CookieAccess":
        obj_uri = ORD2I[f"Cookie_{event_id:06d}"]
        g.add((obj_uri, RDF.type, ORD2I.Cookie))
        g.add((obj_uri, ORD2I.hasRawMessage, Literal(message[:200])))
        m = re.search(r'(https?://\S+)\s*\(([^)]+)\)', message)
        if m:
            g.add((obj_uri, ORD2I.hasCookieDomain, Literal(m.group(1))))
            g.add((obj_uri, ORD2I.hasCookieName,   Literal(m.group(2))))
        g.add((ev_uri, ORD2I.uses, obj_uri))

    elif evt_type == "BookmarkOp":
        obj_uri = ORD2I[f"Bookmark_{event_id:06d}"]
        g.add((obj_uri, RDF.type,            ORD2I.Bookmark))
        g.add((obj_uri, ORD2I.hasRawMessage, Literal(message[:200])))
        g.add((ev_uri, ORD2I.uses, obj_uri))

    elif evt_type == "FileDownload":
        obj_uri = ORD2I[f"DownloadedFile_{event_id:06d}"]
        g.add((obj_uri, RDF.type,            ORD2I.DownloadedFile))
        if url:
            g.add((obj_uri, ORD2I.hasURL,    Literal(url, datatype=XSD.anyURI)))
        if file_path:
            g.add((obj_uri, ORD2I.hasFilePath, Literal(file_path)))
        g.add((obj_uri, ORD2I.hasRawMessage, Literal(message[:200])))
        g.add((ev_uri, ORD2I.uses, obj_uri))

    # ── SKL Object — Execution ─────────────────────────────
    elif evt_type in ("AppExecution", "AppInstall"):
        # Coba reuse instance yang sama untuk exe yang sama
        key = safe_uri(app_name or file_path or message[:30])
        obj_uri = ORD2I[f"ProcessExec_{key}"]
        if (obj_uri, RDF.type, ORD2I.ProcessExecution) not in g:
            g.add((obj_uri, RDF.type, ORD2I.ProcessExecution))
            if app_name:
                g.add((obj_uri, ORD2I.hasProcessName, Literal(app_name)))
            if file_path:
                g.add((obj_uri, ORD2I.hasFilePath,    Literal(file_path[:200])))
        # Tambahkan run count dari message jika ada
        m = re.search(r'[Rr]un count:\s*(\d+)', message)
        if m:
            g.add((obj_uri, ORD2I.hasRunCount, Literal(int(m.group(1)), datatype=XSD.integer)))
        g.add((ev_uri, ORD2I.uses, obj_uri))

    elif evt_type == "AppLaunch":
        key = safe_uri(app_name or file_path or message[:30])
        obj_uri = ORD2I[f"ExeFile_{key}"]
        if (obj_uri, RDF.type, ORD2I.ExeFile) not in g:
            g.add((obj_uri, RDF.type,         ORD2I.ExeFile))
            if app_name:
                g.add((obj_uri, ORD2I.hasAppName,  Literal(app_name)))
            if file_path:
                g.add((obj_uri, ORD2I.hasFilePath, Literal(file_path[:200])))
        g.add((ev_uri, ORD2I.uses, obj_uri))

    # ── SKL Object — Registry ──────────────────────────────
    elif evt_type in ("RegistryModify", "AutoRun"):
        obj_uri = ORD2I[f"RegKey_{event_id:06d}"]
        g.add((obj_uri, RDF.type, ORD2I.RegistryKey))
        if reg_key:
            g.add((obj_uri, ORD2I.hasRegistryKey, Literal(reg_key)))
        g.add((obj_uri, ORD2I.hasRawMessage, Literal(message[:200])))
        g.add((ev_uri, ORD2I.uses, obj_uri))

    elif evt_type == "ServiceModify":
        obj_uri = ORD2I[f"Service_{event_id:06d}"]
        g.add((obj_uri, RDF.type, ORD2I.WindowsService))
        g.add((obj_uri, ORD2I.hasRawMessage, Literal(message[:200])))
        m2 = re.search(r'[Ss]ervice [Nn]ame:\s*(\S+)', message)
        if m2:
            g.add((obj_uri, ORD2I.hasServiceName, Literal(m2.group(1))))
        g.add((ev_uri, ORD2I.uses, obj_uri))

    elif evt_type == "TaskSchedule":
        obj_uri = ORD2I[f"Task_{event_id:06d}"]
        g.add((obj_uri, RDF.type,            ORD2I.ScheduledTask))
        g.add((obj_uri, ORD2I.hasRawMessage, Literal(message[:200])))
        g.add((ev_uri, ORD2I.uses, obj_uri))

    # ── SKL Object — System Events ─────────────────────────
    elif evt_type in ("UserLogon", "ProcessCreate", "SystemEvent"):
        obj_uri = ORD2I[f"EvtEntry_{event_id:06d}"]
        g.add((obj_uri, RDF.type, ORD2I.EventLogEntry))
        # Event ID dari winevtx message
        m3 = re.search(r'[Ee]vent [Ii][Dd]:\s*(\d+)', message)
        if m3:
            g.add((obj_uri, ORD2I.hasEventID,
                   Literal(int(m3.group(1)), datatype=XSD.integer)))
        g.add((obj_uri, ORD2I.hasRawMessage, Literal(message[:200])))
        g.add((ev_uri, ORD2I.uses, obj_uri))

    # ── SKL Object — LNK / FileAccess ─────────────────────
    elif evt_type == "FileAccess":
        obj_uri = ORD2I[f"FileObj_{event_id:06d}"]
        g.add((obj_uri, RDF.type, ORD2I.ShortcutFile if "lnk" in parser else ORD2I.File))
        if file_path:
            g.add((obj_uri, ORD2I.hasFilePath, Literal(file_path[:200])))
        g.add((obj_uri, ORD2I.hasRawMessage, Literal(message[:200])))
        g.add((ev_uri, ORD2I.uses, obj_uri))

    # ── SKL Object — Filesystem ────────────────────────────
    else:
        obj_uri = ORD2I[f"FileObj_{event_id:06d}"]
        g.add((obj_uri, RDF.type, ORD2I.File))
        if file_path:
            g.add((obj_uri, ORD2I.hasFilePath, Literal(file_path[:200])))
        if message:
            g.add((obj_uri, ORD2I.hasRawMessage, Literal(message[:200])))
        g.add((ev_uri, ORD2I.uses, obj_uri))

    # ── TKL: hubungkan ke InvestigativeOperation ───────────
    g.add((op_uri, ORD2I.identifiedBy, ev_uri))

    return ev_uri


# ============================================================
# MAIN
# ============================================================

def main():
    print("=" * 60)
    print("STEP 2 — Instansiasi Ontologi ORD2I (Full Scenario)")
    print("=" * 60)

    try:
        df = pd.read_csv(INPUT_FILE, dtype=str)
    except FileNotFoundError:
        print(f"[ERROR] '{INPUT_FILE}' tidak ditemukan.")
        print("Jalankan Step 1 terlebih dahulu.")
        sys.exit(1)
    df = df.fillna("")

    print(f"[INFO] Memuat {len(df):,} events dari {INPUT_FILE}")

    g = Graph()
    g.bind("ord2i", ORD2I)
    g.bind("time",  TIME)
    g.bind("prov",  PROV)
    g.bind("owl",   OWL)
    g.bind("xsd",   XSD)
    g.bind("rdfs",  RDFS)

    # Schema
    build_schema(g)

    # TKL instances
    op_uri, tool_uri, inv_uri = build_tkl(g)

    # Subject instances
    user_uri = ORD2I.Person_User
    g.add((user_uri, RDF.type,           ORD2I.Person))
    g.add((user_uri, ORD2I.hasUsername,  Literal("User")))
    g.add((user_uri, RDFS.label,         Literal("Windows user: User")))
    g.add((op_uri,   ORD2I.identifiedBy, user_uri))

    sys_uri = ORD2I.Process_WindowsSystem
    g.add((sys_uri, RDF.type,   ORD2I.Process))
    g.add((sys_uri, RDFS.label, Literal("Windows 11 Enterprise system processes")))
    g.add((op_uri,  ORD2I.identifiedBy, sys_uri))

    account_uri = ORD2I.WinUserAccount_User
    g.add((account_uri, RDF.type,           ORD2I.WinUserAccount))
    g.add((account_uri, ORD2I.hasUsername,  Literal("User")))
    g.add((account_uri, ORD2I.hasFilePath,  Literal(r"C:\Users\User")))

    # Instantiate events
    print(f"\n[INFO] Menginstansiasi {len(df):,} events ke ORD2I triples...")
    event_count = 0
    for i, row in df.iterrows():
        instantiate_event(g, row, i + 1, op_uri, user_uri, sys_uri)
        event_count += 1
        if event_count % BATCH_SIZE == 0:
            pct = event_count / len(df) * 100
            print(f"       ... {event_count:,}/{len(df):,} ({pct:.0f}%)")

    # Serialize
    print(f"\n[INFO] Menyimpan ke {OUTPUT_FILE}...")
    g.serialize(OUTPUT_FILE, format="turtle")

    triple_count = len(g)
    print(f"\n[OK] {OUTPUT_FILE}")
    print(f"     Events   : {event_count:,}")
    print(f"     Triples  : {triple_count:,}")
    print(f"     Estimasi : ~{triple_count//event_count} triple/event rata-rata")
    print(f"\n[SELESAI] Lanjutkan ke Step 3: python3 03_sparql_analysis_full.py")


if __name__ == "__main__":
    main()
