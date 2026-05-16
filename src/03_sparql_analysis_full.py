"""
==========================================================
STEP 3 — ANALISIS SPARQL (FULL SCENARIO 1)
==========================================================

10 QUERY SPARQL:
  Q1  - Timeline kronologis semua event
  Q2  - Kunjungan web (WebpageVisit)
  Q3  - Pencarian web (WebSearch)
  Q4  - Cookie yang diterima
  Q5  - Traceability TKL
  Q6  - Eksekusi aplikasi (AppExecution/AppLaunch)
  Q7  - Operasi file system (Create/Modify/Delete)
  Q8  - Modifikasi registri
  Q9  - System events (Logon/ProcessCreate)
  Q10 - Ringkasan statistik per event type

INPUT  : scenario1_ord2i_full.ttl
OUTPUT : hasil_sparql_full/*.csv
"""

import csv
import os
from rdflib import Graph, Namespace
from collections import Counter

csv.field_size_limit(10 ** 7)

RDF_INPUT  = "scenario1_ord2i_full.ttl"
OUTPUT_DIR = "hasil_sparql_full"
os.makedirs(OUTPUT_DIR, exist_ok=True)

ORD2I = Namespace("http://example.org/ord2i#")


# ============================================================
# HELPER
# ============================================================

def run_query(g, name, sparql, columns, description):
    print(f"\n{'='*55}")
    print(f"[{name}] {description}")
    print('='*55)

    results = list(g.query(sparql))
    print(f"  Hasil: {len(results)} baris")

    if not results:
        print("  (tidak ada hasil)")
        return []

    path = os.path.join(OUTPUT_DIR, f"{name}.csv")
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(columns)
        for row in results:
            w.writerow([str(v) if v else "" for v in row])

    print(f"  Disimpan: {path}")
    for i, row in enumerate(results[:5]):
        vals = [str(v)[:70] if v else "" for v in row]
        print(f"  {i+1}. {' | '.join(vals)}")
    if len(results) > 5:
        print(f"  ... +{len(results)-5} baris lagi")

    return results


# ============================================================
# MAIN
# ============================================================

def main():
    print("=" * 60)
    print("STEP 3 — Analisis SPARQL Full Scenario 1")
    print("=" * 60)

    print(f"\n[INFO] Memuat {RDF_INPUT}...")
    g = Graph()
    g.parse(RDF_INPUT, format="turtle")
    print(f"[INFO] {len(g):,} triples dimuat")

    PFX = """
    PREFIX ord2i: <http://example.org/ord2i#>
    PREFIX time:  <http://www.w3.org/2006/time#>
    PREFIX xsd:   <http://www.w3.org/2001/XMLSchema#>
    PREFIX rdfs:  <http://www.w3.org/2000/01/rdf-schema#>
    """

    # ──────────────────────────────────────────────────────
    # Q1: Timeline kronologis SEMUA event
    # ──────────────────────────────────────────────────────
    run_query(g, "Q1_timeline_full", PFX + """
    SELECT ?event ?eventType ?time ?parser ?source
    WHERE {
        ?event a ord2i:Event ;
               ord2i:hasEventType ?eventType ;
               ord2i:hasParser    ?parser ;
               ord2i:hasSource    ?source .
        OPTIONAL {
            ?event ord2i:hasTimeInterval ?iv .
            ?iv time:hasBeginning ?time .
        }
    }
    ORDER BY ?time
    """,
    ["event", "event_type", "timestamp", "parser", "source"],
    "Timeline kronologis semua event Scenario 1")

    # ──────────────────────────────────────────────────────
    # Q2: WebpageVisit
    # ──────────────────────────────────────────────────────
    run_query(g, "Q2_webpage_visits", PFX + """
    SELECT ?time ?url ?hostname ?title
    WHERE {
        ?event a ord2i:Event ;
               ord2i:hasEventType "WebpageVisit" ;
               ord2i:uses ?obj .
        ?obj a ord2i:Webpage ;
             ord2i:hasURL ?url .
        OPTIONAL { ?obj ord2i:hasHostname  ?hostname }
        OPTIONAL { ?obj ord2i:hasPageTitle ?title }
        OPTIONAL {
            ?event ord2i:hasTimeInterval ?iv .
            ?iv time:hasBeginning ?time .
        }
    }
    ORDER BY ?time
    """,
    ["timestamp", "url", "hostname", "title"],
    "Semua halaman web yang dikunjungi")

    # ──────────────────────────────────────────────────────
    # Q3: WebSearch
    # ──────────────────────────────────────────────────────
    run_query(g, "Q3_web_searches", PFX + """
    SELECT ?time ?url ?description
    WHERE {
        ?event a ord2i:Event ;
               ord2i:hasEventType "WebSearch" ;
               ord2i:uses ?obj .
        ?obj a ord2i:WebResource ;
             ord2i:hasURL ?url .
        OPTIONAL { ?obj ord2i:hasDescription ?description }
        OPTIONAL {
            ?event ord2i:hasTimeInterval ?iv .
            ?iv time:hasBeginning ?time .
        }
    }
    ORDER BY ?time
    """,
    ["timestamp", "url", "description"],
    "Semua kueri pencarian web")

    # ──────────────────────────────────────────────────────
    # Q4: CookieAccess
    # ──────────────────────────────────────────────────────
    run_query(g, "Q4_cookie_access", PFX + """
    SELECT ?time ?cookieName ?cookieDomain ?message
    WHERE {
        ?event a ord2i:Event ;
               ord2i:hasEventType "CookieAccess" ;
               ord2i:uses ?obj .
        ?obj a ord2i:Cookie .
        OPTIONAL { ?obj ord2i:hasCookieName   ?cookieName }
        OPTIONAL { ?obj ord2i:hasCookieDomain ?cookieDomain }
        OPTIONAL { ?obj ord2i:hasRawMessage   ?message }
        OPTIONAL {
            ?event ord2i:hasTimeInterval ?iv .
            ?iv time:hasBeginning ?time .
        }
    }
    ORDER BY ?time
    """,
    ["timestamp", "cookie_name", "cookie_domain", "message"],
    "Cookie yang diterima selama sesi")

    # ──────────────────────────────────────────────────────
    # Q5: Traceability TKL
    # ──────────────────────────────────────────────────────
    run_query(g, "Q5_traceability_tkl", PFX + """
    SELECT ?operation ?technique ?infoSource ?confidence
           ?toolName ?investigatorName
    WHERE {
        ?operation a ord2i:InvestigativeOperation ;
                   ord2i:hasTechnique  ?technique ;
                   ord2i:hasInfoSource ?infoSource ;
                   ord2i:hasConfidence ?confidence .
        OPTIONAL {
            ?operation ord2i:isPerformedWith ?tool .
            ?tool ord2i:hasToolName ?toolName .
        }
        OPTIONAL {
            ?operation ord2i:hasContribution ?contrib .
            ?contrib ord2i:hasContribution ?inv .
            ?inv ord2i:hasInvestigatorName ?investigatorName .
        }
    }
    """,
    ["operation", "technique", "info_source", "confidence",
     "tool_name", "investigator"],
    "TKL — Operasi investigasi (traceability)")

    # ──────────────────────────────────────────────────────
    # Q6: AppExecution + AppInstall (prefetch, amcache, BAM)
    # ──────────────────────────────────────────────────────
    run_query(g, "Q6_app_execution", PFX + """
    SELECT ?time ?eventType ?processName ?filePath ?runCount ?parser
    WHERE {
        ?event a ord2i:Event ;
               ord2i:hasEventType ?eventType ;
               ord2i:hasParser    ?parser ;
               ord2i:uses ?obj .
        FILTER(?eventType IN ("AppExecution", "AppInstall", "AppLaunch"))
        OPTIONAL { ?obj ord2i:hasProcessName ?processName }
        OPTIONAL { ?obj ord2i:hasFilePath    ?filePath }
        OPTIONAL { ?obj ord2i:hasRunCount    ?runCount }
        OPTIONAL { ?obj ord2i:hasAppName     ?processName }
        OPTIONAL {
            ?event ord2i:hasTimeInterval ?iv .
            ?iv time:hasBeginning ?time .
        }
    }
    ORDER BY ?time
    """,
    ["timestamp", "event_type", "process_name", "file_path",
     "run_count", "parser"],
    "Eksekusi aplikasi (prefetch/amcache/BAM/LNK)")

    # ──────────────────────────────────────────────────────
    # Q7: File System Operations
    # ──────────────────────────────────────────────────────
    run_query(g, "Q7_filesystem_ops", PFX + """
    SELECT ?time ?eventType ?filePath ?parser ?message
    WHERE {
        ?event a ord2i:Event ;
               ord2i:hasEventType ?eventType ;
               ord2i:hasParser    ?parser .
        FILTER(?eventType IN ("FileCreate", "FileModify", "FileDelete",
                              "FileAccess", "FileDownload", "FileSystemOp"))
        OPTIONAL { ?event ord2i:uses ?obj .
                   ?obj ord2i:hasFilePath ?filePath }
        OPTIONAL { ?event ord2i:hasRawMessage ?message }
        OPTIONAL {
            ?event ord2i:hasTimeInterval ?iv .
            ?iv time:hasBeginning ?time .
        }
    }
    ORDER BY ?time
    LIMIT 500
    """,
    ["timestamp", "event_type", "file_path", "parser", "message"],
    "Operasi file system (500 teratas)")

    # ──────────────────────────────────────────────────────
    # Q8: Registry Modifications
    # ──────────────────────────────────────────────────────
    run_query(g, "Q8_registry_mods", PFX + """
    SELECT ?time ?eventType ?registryKey ?parser ?message
    WHERE {
        ?event a ord2i:Event ;
               ord2i:hasEventType ?eventType ;
               ord2i:hasParser    ?parser .
        FILTER(?eventType IN ("RegistryModify", "AutoRun", "ServiceModify"))
        OPTIONAL { ?event ord2i:uses ?obj .
                   ?obj ord2i:hasRegistryKey ?registryKey }
        OPTIONAL { ?event ord2i:hasRawMessage ?message }
        OPTIONAL {
            ?event ord2i:hasTimeInterval ?iv .
            ?iv time:hasBeginning ?time .
        }
    }
    ORDER BY ?time
    """,
    ["timestamp", "event_type", "registry_key", "parser", "message"],
    "Modifikasi registri Windows")

    # ──────────────────────────────────────────────────────
    # Q9: System Events (Logon, ProcessCreate)
    # ──────────────────────────────────────────────────────
    run_query(g, "Q9_system_events", PFX + """
    SELECT ?time ?eventType ?eventId ?message ?parser
    WHERE {
        ?event a ord2i:Event ;
               ord2i:hasEventType ?eventType ;
               ord2i:hasParser    ?parser .
        FILTER(?eventType IN ("UserLogon", "ProcessCreate", "SystemEvent",
                              "TaskSchedule"))
        OPTIONAL { ?event ord2i:uses ?obj .
                   ?obj ord2i:hasEventID ?eventId }
        OPTIONAL { ?event ord2i:hasRawMessage ?message }
        OPTIONAL {
            ?event ord2i:hasTimeInterval ?iv .
            ?iv time:hasBeginning ?time .
        }
    }
    ORDER BY ?time
    """,
    ["timestamp", "event_type", "event_id", "message", "parser"],
    "System events (logon/process/task)")

    # ──────────────────────────────────────────────────────
    # Q10: Statistik per event type
    # ──────────────────────────────────────────────────────
    run_query(g, "Q10_event_stats", PFX + """
    SELECT ?eventType (COUNT(?event) AS ?count)
    WHERE {
        ?event a ord2i:Event ;
               ord2i:hasEventType ?eventType .
    }
    GROUP BY ?eventType
    ORDER BY DESC(?count)
    """,
    ["event_type", "count"],
    "Statistik jumlah event per tipe")

    # ──────────────────────────────────────────────────────
    # Narasi timeline gabungan untuk LLM
    # ──────────────────────────────────────────────────────
    print("\n[INFO] Membangun narasi timeline gabungan untuk LLM...")

    q_narasi = PFX + """
    SELECT ?time ?eventType ?url ?title ?description ?filePath
           ?processName ?registryKey ?message
    WHERE {
        ?event a ord2i:Event ;
               ord2i:hasEventType ?eventType .
        OPTIONAL {
            ?event ord2i:hasTimeInterval ?iv .
            ?iv time:hasBeginning ?time .
        }
        OPTIONAL {
            ?event ord2i:uses ?obj .
            OPTIONAL { ?obj ord2i:hasURL          ?url }
            OPTIONAL { ?obj ord2i:hasPageTitle    ?title }
            OPTIONAL { ?obj ord2i:hasDescription  ?description }
            OPTIONAL { ?obj ord2i:hasFilePath     ?filePath }
            OPTIONAL { ?obj ord2i:hasProcessName  ?processName }
            OPTIONAL { ?obj ord2i:hasRegistryKey  ?registryKey }
        }
        OPTIONAL { ?event ord2i:hasRawMessage ?message }
    }
    ORDER BY ?time
    """

    from datetime import datetime as dt_cls
    rows_narasi = list(g.query(q_narasi))
    lines = []
    lines.append("=== FORENSIC TIMELINE — Scenario 1 Full ===")
    lines.append("Dataset : Zenodo Scenario 1 (Studiawan et al., 2025)")
    lines.append("OS      : Windows 11 Enterprise, 2023-12-26")
    lines.append("Tool    : log2timeline/Plaso, ORD2I ontology")
    lines.append("=" * 55)
    lines.append("")

    for row in rows_narasi:
        time_val = str(row[0]) if row[0] else "?"
        evt_type = str(row[1]) if row[1] else "Unknown"
        url      = str(row[2]) if row[2] else ""
        title    = str(row[3]) if row[3] else ""
        desc     = str(row[4]) if row[4] else ""
        fpath    = str(row[5]) if row[5] else ""
        proc     = str(row[6]) if row[6] else ""
        reg      = str(row[7]) if row[7] else ""
        msg      = str(row[8]) if row[8] else ""

        try:
            t = dt_cls.fromisoformat(time_val.replace("+00:00",""))
            ts = t.strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            ts = time_val

        if evt_type == "WebpageVisit":
            lines.append(f"[{ts}] WEB VISIT : {title or url}")
            if url: lines.append(f"             URL: {url}")
        elif evt_type == "WebSearch":
            q = desc.replace("Search query: ","") if desc else url
            lines.append(f"[{ts}] WEB SEARCH: {q}")
        elif evt_type == "CookieAccess":
            lines.append(f"[{ts}] COOKIE    : {msg[:80]}")
        elif evt_type in ("AppExecution","AppInstall"):
            lines.append(f"[{ts}] APP EXEC  : {proc or fpath or msg[:60]}")
        elif evt_type == "AppLaunch":
            lines.append(f"[{ts}] APP LAUNCH: {proc or fpath or msg[:60]}")
        elif evt_type == "FileDownload":
            lines.append(f"[{ts}] DOWNLOAD  : {url or fpath or msg[:60]}")
        elif evt_type in ("FileCreate","FileModify","FileDelete"):
            lines.append(f"[{ts}] {evt_type.upper():<12}: {fpath or msg[:60]}")
        elif evt_type == "RegistryModify":
            lines.append(f"[{ts}] REG MODIFY: {reg[:60] or msg[:60]}")
        elif evt_type == "AutoRun":
            lines.append(f"[{ts}] AUTORUN   : {reg[:60] or msg[:60]}")
        elif evt_type == "UserLogon":
            lines.append(f"[{ts}] USER LOGON: {msg[:80]}")
        elif evt_type == "ProcessCreate":
            lines.append(f"[{ts}] PROC CREATE: {msg[:80]}")
        elif evt_type == "SystemEvent":
            lines.append(f"[{ts}] SYS EVENT : {msg[:80]}")
        else:
            lines.append(f"[{ts}] {evt_type:<14}: {fpath or msg[:60]}")

    narasi_text = "\n".join(lines)
    narasi_path = os.path.join(OUTPUT_DIR, "full_narasi_timeline.txt")
    with open(narasi_path, "w", encoding="utf-8") as f:
        f.write(narasi_text)
    print(f"  [OK] Narasi: {narasi_path} ({len(lines)} baris)")

    print(f"\n[SELESAI] Semua query selesai. Direktori: {OUTPUT_DIR}/")
    print(f"          Lanjutkan ke Step 4: python3 04_event_correlation_full.py")


if __name__ == "__main__":
    main()
