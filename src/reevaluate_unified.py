"""
==========================================================
PERBAIKAN — Ground Truth Tunggal untuk Local & Cloud
==========================================================

MASALAH YANG DIPERBAIKI:
  Skrip 05_llm_report_multimodel.py (local) dan 05_llm_openrouter_tiers.py
  (cloud) masing-masing memakai GROUND_TRUTH yang BERBEDA panjang dan isinya
  (309 kata vs 441 kata). Perbaikan dilakukan untuk perbandingan BLEU/ROUGE 
  local-vs-cloud di Tabel 4.

CATATAN:
  1. Memuat SATU ground truth resmi dari ground_truth_final.txt
  2. Membaca ULANG ke-18 file laporan LLM yang SUDAH ADA di:
       hasil_sparql/*.txt        (3 model lokal x 3 skenario = 9 file)
       hasil_sparql_full/*.txt   (3 model cloud x 3 skenario = 9 file)
     -> TIDAK memanggil ulang Ollama / OpenRouter. Laporan mentah
        yang sudah pernah dihasilkan LLM tetap dipakai apa adanya, 
        dan diulang hanyalah proses PENSKORANNYA.
  3. Menghitung ulang BLEU/ROUGE-1/ROUGE-2/ROUGE-L dengan library resmi
     (evaluate + sacrebleu + rouge-score) terhadap ground truth tunggal.
  4. Menyimpan hasil ke unified_evaluation_final.csv

"""

import os
import re
import csv
import glob

# ============================================================
# KONFIGURASI
# ============================================================

GROUND_TRUTH_FILE = "ground_truth_final.txt"
OUTPUT_CSV        = "unified_evaluation_final.csv"

REPORT_DIRS = ["hasil_sparql", "hasil_sparql_full"]

# WHITELIST: hanya 6 model final yang dilaporkan di paper (Section 3.6 & Tabel 4).
# Model lain yang mungkin ikut tersimpan di folder yang sama (mis. percobaan
# yang gagal/dibatalkan seperti gemini_flash, mistral_7b) SENGAJA dikecualikan
# di sini supaya rata-rata Local/Cloud tidak bias oleh model di luar cakupan
# resmi penelitian. Sesuaikan daftar ini jika nama model di file Anda berbeda.
MODEL_WHITELIST = {
    "qwen2_5_0_5b",
    "qwen2_5_1_5b",
    "tinyllama_latest",
    "openrouter_llama_8b",
    "openrouter_qwen_72b",
    "openrouter_qwen_7b",
}

# Pola nama file: <model>_<scenario>_report.txt
FNAME_RE = re.compile(
    r"^(?P<model>.+?)_(?P<scenario>S[123]_[a-z_]+)_report\.txt$"
)

SCENARIO_LABELS = {
    "S1_without_knowledge": "S1 - Baseline",
    "S2_with_knowledge":    "S2 - ORD2I-augmented",
    "S3_few_shot":          "S3 - Few-shot",
}


# ============================================================
# 1. MUAT GROUND TRUTH TUNGGAL
# ============================================================

def load_ground_truth():
    if not os.path.exists(GROUND_TRUTH_FILE):
        raise FileNotFoundError(
            f"'{GROUND_TRUTH_FILE}' tidak ditemukan. Letakkan file ini "
            f"sejajar dengan skrip ini sebelum menjalankan."
        )
    with open(GROUND_TRUTH_FILE, encoding="utf-8") as f:
        return f.read().strip()


# ============================================================
# 2. BACA & BERSIHKAN LAPORAN LLM YANG SUDAH ADA
# ============================================================

def extract_report_body(path):
    """
    File laporan punya header metadata lama (BLEU/ROUGE versi lama,
    provider, waktu, dst.) dipisahkan oleh baris '====...'.
    Kita ambil HANYA teks laporan asli LLM (setelah separator terakhir),
    supaya skor lama tidak ikut mempengaruhi teks yang dinilai ulang.
    """
    with open(path, encoding="utf-8", errors="replace") as f:
        content = f.read()
    parts = content.split("=" * 60)
    body = parts[-1].strip() if len(parts) > 1 else content.strip()
    return body


def collect_reports():
    reports = []
    excluded = []
    for d in REPORT_DIRS:
        if not os.path.isdir(d):
            print(f"  [WARN] folder '{d}' tidak ditemukan, dilewati")
            continue
        provider = "Local (Ollama)" if d == "hasil_sparql" else "Cloud (OpenRouter)"
        for path in sorted(glob.glob(os.path.join(d, "*_report.txt"))):
            fname = os.path.basename(path)
            m = FNAME_RE.match(fname)
            if not m:
                continue
            model    = m.group("model")
            scenario = m.group("scenario")
            if model not in MODEL_WHITELIST:
                excluded.append(fname)
                continue
            body = extract_report_body(path)
            reports.append({
                "provider": provider,
                "model": model,
                "scenario": scenario,
                "scenario_label": SCENARIO_LABELS.get(scenario, scenario),
                "path": path,
                "text": body,
            })
    if excluded:
        print(f"  [INFO] {len(excluded)} file DIKECUALIKAN (di luar "
              f"MODEL_WHITELIST, mis. percobaan model yang gagal/dibatalkan):")
        for fn in excluded:
            print(f"           - {fn}")
    return reports


# ============================================================
# 3. BLEU / ROUGE (library resmi — SAMA seperti skrip asli)
# ============================================================

def compute_bleu_rouge(hypothesis, reference):
    try:
        import evaluate as ev
        b = ev.load("bleu").compute(
            predictions=[hypothesis], references=[[reference]])
        r = ev.load("rouge").compute(
            predictions=[hypothesis], references=[reference])
        return {
            "bleu":   round(b.get("bleu", 0), 4),
            "rouge1": round(r.get("rouge1", 0), 4),
            "rouge2": round(r.get("rouge2", 0), 4),
            "rougeL": round(r.get("rougeL", 0), 4),
            "method": "evaluate",
        }
    except ImportError:
        print("  [WARN] library 'evaluate' tidak tersedia — fallback "
              "word-overlap dipakai. Hasil TIDAK setara dengan Tabel 4 "
              "asli. Install: pip install evaluate sacrebleu rouge-score")
        hw = set(hypothesis.lower().split())
        rw = set(reference.lower().split())
        ov = len(hw & rw)
        pr = ov / len(hw) if hw else 0
        rc = ov / len(rw) if rw else 0
        f1 = 2 * pr * rc / (pr + rc) if pr + rc > 0 else 0
        return {"bleu": round(pr, 4), "rouge1": round(f1, 4),
                "rouge2": 0.0, "rougeL": round(f1, 4), "method": "word-overlap"}


# ============================================================
# MAIN
# ============================================================

def main():
    print("=" * 60)
    print("RE-EVALUASI TERPADU — Ground Truth Tunggal")
    print("=" * 60)

    reference = load_ground_truth()
    print(f"Ground truth dimuat: {len(reference.split())} kata, "
          f"{len(reference)} karakter")

    reports = collect_reports()
    print(f"Laporan ditemukan: {len(reports)} file "
          f"(diharapkan 18: 9 lokal + 9 cloud)\n")

    rows = []
    for r in reports:
        print(f"  -> {r['provider']:<18} {r['model']:<20} {r['scenario_label']}")
        scores = compute_bleu_rouge(r["text"], reference)
        mean_s = round(sum(scores[k] for k in
                            ["bleu", "rouge1", "rouge2", "rougeL"]) / 4, 4)

        rows.append({
            "provider": r["provider"],
            "model": r["model"],
            "scenario": r["scenario_label"],
            "bleu": scores["bleu"],
            "rouge1": scores["rouge1"],
            "rouge2": scores["rouge2"],
            "rougeL": scores["rougeL"],
            "mean": mean_s,
            "eval_method": scores["method"],
            "source_file": r["path"],
        })
        print(f"     BLEU={scores['bleu']:.4f} R1={scores['rouge1']:.4f} "
              f"R2={scores['rouge2']:.4f} RL={scores['rougeL']:.4f} "
              f"Mean={mean_s:.4f}")

    # Simpan CSV
    if rows:
        with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
            w.writeheader()
            w.writerows(rows)
        print(f"\nHasil disimpan: {OUTPUT_CSV}")

        local_rows = [r for r in rows if r["provider"].startswith("Local")]
        cloud_rows = [r for r in rows if r["provider"].startswith("Cloud")]
        if local_rows:
            print(f"\nLocal average (mean, n={len(local_rows)}): "
                  f"{sum(r['mean'] for r in local_rows)/len(local_rows):.4f}")
        if cloud_rows:
            print(f"Cloud average (mean, n={len(cloud_rows)}): "
                  f"{sum(r['mean'] for r in cloud_rows)/len(cloud_rows):.4f}")

    print("\nCATATAN PENTING:")
    print("  - Kolom Fcov TIDAK disertakan (dihapus dari metodologi -- lihat")
    print("    Section 3.6/5.4 revisi naskah untuk justifikasinya).")
    print("  - Bandingkan unified_evaluation_final.csv dengan Tabel 4 lama")
    print("    untuk melihat seberapa besar perubahan setelah ground truth")
    print("    disatukan.")


if __name__ == "__main__":
    main()
