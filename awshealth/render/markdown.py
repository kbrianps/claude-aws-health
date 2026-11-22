from __future__ import annotations

import json
import re
from pathlib import Path

from .common import (
    Run,
    by_owner,
    cap,
    coh_usd,
    dated,
    days_until,
    fmt_usd,
    high_count,
    nearest_deadline,
    note_lines,
    owner_text,
    total_usd,
    utc_text,
)
from .i18n import strings

START_HERE = 7


def md(value, n: int = 2000) -> str:
    s = cap(value, n).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return s.replace("[", "\\[").replace("]", "\\]")


def cell(value, n: int = 300) -> str:
    return re.sub(r"\s*\n\s*", " ", md(value, n)).replace("|", "\\|")


def code(value, n: int = 1000) -> str:
    s = re.sub(r"\s*\n\s*", " ", cap(value, n))
    ticks = "`" * (max((len(m) for m in re.findall(r"`+", s)), default=0) + 1)
    pad = " " if s.startswith("`") or s.endswith("`") else ""
    return f"{ticks}{pad}{s}{pad}{ticks}"


def fence(value, n: int = 1000) -> str:
    s = cap(value, n)
    ticks = "`" * max(3, max((len(m) for m in re.findall(r"`+", s)), default=0) + 1)
    return f"{ticks}sh\n{s}\n{ticks}"


def sev(severity: str, s: dict) -> str:
    return s.get("sev_" + severity, severity).upper()


def meta_lines(run: Run, s: dict) -> list[str]:
    m = run.meta
    return [
        f"- {s['account']}: {code(m.get('account_id', ''), 40)}",
        f"- {s['regions']}: {md(', '.join(m.get('regions') or []), 600)}",
        f"- {s['collected_at']}: {md(utc_text(m.get('collected_at', '')) or s['none'])}",
        f"- {s['tool_version']}: {md(run.version)}",
        "",
        f"> {md(s['read_only'])}",
    ]


def kpi_lines(run: Run, s: dict, lang: str) -> list[str]:
    near = nearest_deadline(run)
    if near:
        n = days_until(near.deadline, run.now)
        rel = s["today"] if n == 0 else s["in_days"].replace("{n}", str(n))
        deadline = (f"{utc_text(near.deadline, False)} ({rel}), "
                    f"{md(near.t('title', lang), 140)}")
    else:
        deadline = s["kpi_deadline_none"]
    cov = run.coverage
    coh = coh_usd(run)
    return [
        f"- {s['kpi_deadline']}: {deadline}",
        f"- {s['kpi_usd']}: {fmt_usd(total_usd(run), lang)} ({s['kpi_usd_note'].lower()})",
        *([f"- {s['kpi_coh']}: {fmt_usd(coh, lang)} ({s['kpi_coh_note']})"] if coh else []),
        f"- {s['kpi_high']}: {high_count(run)}",
        f"- {s['kpi_coverage']}: {cov['checked']}/{cov['total']}",
    ]


def short(f, run: Run, s: dict, lang: str) -> str:
    bits = [code(f.check_id, 120), md(f.region, 40)]
    if f.source != "awshealth":
        bits.append(md(f.source, 60))
    if f.monthly_usd:
        bits.append(fmt_usd(f.monthly_usd, lang) + s["per_month"])
    if f.deadline:
        bits.append(f"{s['deadline']} {utc_text(f.deadline, False)}")
    return " · ".join(bits)


def finding_lines(f, run: Run, s: dict, lang: str) -> list[str]:
    out = [f"### [{sev(f.severity, s)}] {cell(f.t('title', lang))}", "", short(f, run, s, lang), "",
           f"- {s['resources']}: " + ", ".join(code(r, 512) for r in f.resources[:20])]
    for key in ("what", "risk", "fix"):
        if f.t(key, lang):
            out.append(f"- {s[key]}: {cell(f.t(key, lang), 2000)}")
    if f.monthly_usd:
        calc = f" ({cell(f.usd_calc, 600)})" if f.usd_calc else ""
        out.append(f"- {s['cost']}: {fmt_usd(f.monthly_usd, lang)}{s['per_month']}{calc}")
    if owner_text(f, lang):
        out.append(f"- {s['owner_question']}: {cell(owner_text(f, lang), 1000)}")
    for note in note_lines(f, lang)[:20]:
        out.append(f"- {s['notes']}: {cell(note, 600)}")
    for c in f.claims[:20]:
        value = c.value if isinstance(c.value, str) else json.dumps(c.value, default=str, ensure_ascii=False)
        out.append(f"- {s['claims']}: {code(c.source, 200)} {code(c.path, 300)} = {cell(value, 300)}")
    if f.verify:
        out += ["", f"{s['verify']}:", ""] + [fence(c) for c in f.verify[:5]]
    return out + [""]


def report(run: Run, lang: str) -> str:
    s = strings(lang)
    out = [f"# {s['report_title']}", "", *meta_lines(run, s), "", *kpi_lines(run, s, lang), ""]
    out += [f"## {s['start_here']}", ""]
    top = run.findings[:START_HERE]
    out += [f"{i}. [{sev(f.severity, s)}] {cell(f.t('title', lang))} ({short(f, run, s, lang)})"
            for i, f in enumerate(top, 1)] or [s["start_here_none"]]
    out += ["", f"## {s['inventory']}", ""]
    for f in run.findings:
        out += finding_lines(f, run, s, lang)
    if not run.findings:
        out += [s["start_here_none"], ""]
    out += [f"## {s['killed']}", ""]
    for k in run.killed:
        out.append(f"- [{sev(k.finding.severity, s)}] {cell(k.finding.t('title', lang))} ({code(k.finding.uid, 160)})")
        out.append(f"  - {s['reason']}: {cell(k.reason, 1000)}")
        out += [f"  - {s['evidence']}: {cell(x, 600)}" for x in k.evidence[:20]]
    if not run.killed:
        out.append(s["killed_none"])
    out += ["", f"## {s['questions']}", ""]
    out += question_lines(run, s, lang, level="###") or [s["questions_none"]]
    out += ["", f"## {s['deadlines']}", ""]
    rows = dated(run)
    if rows:
        out += [f"| {s['deadline']} | {s['severity']} | {s['finding']} | {s['cost']} |", "|---|---|---|---|"]
        for f in rows:
            n = days_until(f.deadline, run.now)
            passed = f" ({s['passed']})" if n is not None and n < 0 else ""
            usd = fmt_usd(f.monthly_usd, lang) + s["per_month"] if f.monthly_usd else ""
            out.append(f"| {utc_text(f.deadline)}{passed} | {sev(f.severity, s)} | {cell(f.t('title', lang), 200)} "
                       f"| {usd} |")
    else:
        out.append(s["deadlines_none"])
    out += ["", f"## {s['coverage']}", "", *count_table(run, s), "", *problem_lines(run, s), ""]
    out += [footer(run, s), ""]
    return "\n".join(out)


def question_lines(run: Run, s: dict, lang: str, level: str = "##") -> list[str]:
    out = []
    for owner, group in by_owner(run, s["unassigned"]):
        out += [f"{level} {s['owner']}: {cell(owner, 120)}", ""]
        for f in group:
            out.append(f"- {cell(owner_text(f, lang), 1000)}")
            out.append(f"  - {s['finding']}: {cell(f.t('title', lang), 200)} ({code(f.resource, 300)})")
        out.append("")
    return out


def count_table(run: Run, s: dict) -> list[str]:
    cov = run.coverage
    rows = [f"| {s['status_' + st]} | {n} |" for st, n in cov["counts"].items()]
    return [f"| {s['status']} | {s['count']} |", "|---|---:|", *rows, f"| {s['total']} | {cov['total']} |"]


def problem_lines(run: Run, s: dict) -> list[str]:
    out = [f"### {s['api_problems']}", ""]
    if not run.api_problems:
        return out + [s["api_problems_none"]]
    for p in run.api_problems[:500]:
        err = f": {cell(p['error'], 300)}" if p["error"] else ""
        out.append(f"- {code(p['call'], 200)} {md(p['region'], 40)} {md(p['status'], 20)}{err}")
    return out


def footer(run: Run, s: dict) -> str:
    if run.calls is None:
        ledger = s["footer_no_ledger"]
    else:
        ledger = s["footer_calls"].replace("{n}", str(run.calls)) + " " + s["footer_blocked"].replace(
            "{n}", str(run.blocked))
    return f"---\n\n{ledger} {s['generated_by'].replace('{v}', run.version)}"


def questions_doc(run: Run, lang: str) -> str:
    s = strings(lang)
    out = [f"# {s['questions']}", "", s["questions_intro"], ""]
    out += question_lines(run, s, lang) or [s["questions_none"], ""]
    return "\n".join(out)


def coverage_doc(run: Run, lang: str) -> str:
    s = strings(lang)
    cov = run.coverage
    out = [f"# {s['coverage']}", "", s["coverage_intro"].replace("{total}", str(cov["total"])), "",
           *count_table(run, s), ""]
    for st in cov["counts"]:
        entries = [x for x in cov["entries"] if x["status"] == st]
        if not entries:
            continue
        out += [f"## {s['status_' + st]} ({len(entries)})", ""]
        for x in entries:
            by = f" ({s['covered_by']}: {', '.join(code(c, 120) for c in x['checks'])})" if x["checks"] else ""
            out.append(f"- {code(x['id'], 120)} {cell(x['title'], 300)}{by}")
        out.append("")
    out += [*problem_lines(run, s), ""]
    return "\n".join(out)


def write(run: Run, lang: str) -> list[Path]:
    docs = {"report.md": report(run, lang), "owner-questions.md": questions_doc(run, lang),
            "coverage.md": coverage_doc(run, lang)}
    paths = []
    for name, text in docs.items():
        path = run.path / name
        path.write_text(text, encoding="utf-8")
        paths.append(path)
    return paths
