"""
CTI Pipeline – Main Orchestrator
Three-stage pipeline: A (LLM extract) → B (ATT&CK map) → C (hunt generate)

Usage:
    python main.py                    # run once (yesterday's articles)
    python main.py --schedule         # daily cron at configured time
    python main.py --lookback 3       # articles from last 3 days
    python main.py --verbose          # debug logging
"""
from __future__ import annotations
import argparse
import logging
import sys
import time
from pathlib import Path

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
RELEVANT_KEYWORDS = [
    "cve",
    "vulnerability", "vulnerable","zero","day","flaw","risk","hackers",
    "exploit","adware","traffic","fake","phishing","hack","bug",
    "rce",
    "zero-day",
    "0day",
    "malware",
    "ransomware",
    "apt",
    "threat actor","exposes","expose",
    "breach","stealth","defense",
    "incident",
    "campaign",
    "ioc","abuse","steal",
    "attack","cyberattack","spy","cybersecurity","breached","exposed","exploitation","exploitated",
    "compromise",
    "privilege escalation",
    "command injection",
    "sql injection",
    "authentication bypass"
]

EXCLUSION_WORDS=["webinar","tutorial","how to","recap","bulletin"]
console = Console()


def setup_logging(verbose: bool = False) -> None:
    logging.basicConfig(
        level   = logging.DEBUG if verbose else logging.INFO,
        format  = "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers = [
            logging.StreamHandler(sys.stdout),
            logging.FileHandler("pipeline.log", mode="a"),
        ],
    )

def is_relevant(title: str, summary: str) -> bool:
    text = f"{title}".lower()
    positive=negative=0
    for k in RELEVANT_KEYWORDS:
        if k in text:
            positive=1
            break
    for j in EXCLUSION_WORDS:
        if j in text:
            negative=1
    return positive >= 1 and not(negative)

def run_pipeline(lookback_days: int = 1) -> dict:
    from rss_ingestor   import ingest_feeds
    from scraper        import extract_articles
    from llm_analyzer   import analyze_articles       # Stage A
    from attack_mapper  import map_reports            # Stage B
    from hunt_generator import generate_all_hypotheses  # Stage C
    from report_generator import save_all_reports, export_ioc_csv
    from database       import save_article, save_report
    from settings       import LLM_MODEL

    stats = {
        "articles_found":    0,
        "articles_extracted": 0,
        "articles_analyzed": 0,
        "attack_mappings":   0,
        "hunt_hypotheses":   0,
        "iocs_extracted":    0,
        "reports_written":   0,
        "elapsed_s":         0.0,
    }
    t0 = time.time()

    with Progress(SpinnerColumn(), TextColumn("{task.description}"),
                  TimeElapsedColumn(), console=console) as prog:

        # ── RSS ───────────────────────────────────────────────────────────────
        t = prog.add_task("[cyan]Stage 1: RSS ingestion...", total=None)
        rss_articles = ingest_feeds(lookback_days=lookback_days)
        stats["articles_found"] = len(rss_articles)
        prog.update(t, description=f"[green]Stage 1 done — {len(rss_articles)} articles")

        if not rss_articles:
            console.print("[yellow]No articles found. Exiting.")
            return stats

    
        rss_articles = [
            a for a in rss_articles
            if is_relevant(a.title, a.summary)
        ]
        # ── Extraction ───────────────────────────────────────────────────────
        t = prog.add_task("[cyan]Stage 2: Extracting content...", total=None)
        extracted = extract_articles(rss_articles[9:10])
        stats["articles_extracted"] = len(extracted)
        prog.update(t, description=f"[green]Stage 2 done — {len(extracted)} extracted")
        for art in extracted:
            save_article(art)
        if not extracted:
            console.print("[yellow]No articles extracted. Exiting.")
            return stats
        # ── Stage A: LLM extraction ───────────────────────────────────────────
        t = prog.add_task(f"[cyan]Stage A: LLM extraction ({LLM_MODEL})...", total=None)
        reports = analyze_articles(extracted)
        stats["articles_analyzed"] = len(reports)
        stats["iocs_extracted"]    = sum(len(r.iocs) for r in reports)
        prog.update(t, description=f"[green]Stage A done — {len(reports)} reports, "
                                   f"{stats['iocs_extracted']} IOCs")

        # ── Stage B: ATT&CK mapping ───────────────────────────────────────────
        t = prog.add_task("[cyan]Stage B: ATT&CK mapping...", total=None)
        reports = map_reports(reports)
        stats["attack_mappings"] = sum(len(r.attack_mappings) for r in reports)
        prog.update(t, description=f"[green]Stage B done — {stats['attack_mappings']} techniques mapped")

        # ── Stage C: Hunt hypotheses ──────────────────────────────────────────
        t = prog.add_task("[cyan]Stage C: Generating hunt hypotheses...", total=None)
        reports = generate_all_hypotheses(reports)
        stats["hunt_hypotheses"] = sum(len(r.hunt_hypotheses) for r in reports)
        prog.update(t, description=f"[green]Stage C done ")
        # ── Persist + output ──────────────────────────────────────────────────
        t = prog.add_task("[cyan]Writing reports...", total=None)
        for r in reports:
            save_report(r)
        paths = save_all_reports(reports)
        export_ioc_csv(reports)
        stats["reports_written"] = len(paths)
        prog.update(t, description=f"[green]Done — {len(paths)} reports written")

    stats["elapsed_s"] = round(time.time() - t0, 1)
    return stats


def print_summary(stats: dict) -> None:
    tbl = Table(title="CTI Pipeline — Run Summary")
    tbl.add_column("Metric",  style="cyan")
    tbl.add_column("Value",   style="white")
    for k, v in stats.items():
        tbl.add_row(k.replace("_", " ").title(), str(v))
    console.print(tbl)


def scheduled_run() -> None:
    import schedule as sched
    from settings import RUN_HOUR, RUN_MINUTE
    run_time = f"{RUN_HOUR:02d}:{RUN_MINUTE:02d}"
    console.print(f"[cyan]Scheduler active — daily run at {run_time} UTC")

    def job():
        console.print("\n[bold cyan]Scheduled pipeline run starting...")
        print_summary(run_pipeline())

    sched.every().day.at(run_time).do(job)
    while True:
        sched.run_pending()
        time.sleep(60)


def main() -> None:
    parser = argparse.ArgumentParser(description="CTI Pipeline")
    parser.add_argument("--schedule",  action="store_true")
    parser.add_argument("--init-rag",  action="store_true")
    parser.add_argument("--lookback",  type=int, default=1)
    parser.add_argument("--verbose",   action="store_true")
    args = parser.parse_args()

    setup_logging(args.verbose)
    Path("data").mkdir(exist_ok=True)
    Path("reports").mkdir(exist_ok=True)
    if args.schedule:
        scheduled_run()
        return

    console.print("[bold cyan]CTI Pipeline — starting run[/]")
    print_summary(run_pipeline(lookback_days=args.lookback))


if __name__ == "__main__":
    main()