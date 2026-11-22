from __future__ import annotations

import re
from datetime import timedelta, timezone
from pathlib import Path

from ..model import Finding
from ..registry import load_checks
from .common import Run, cap, owner_text, parse_ts
from .i18n import strings


def escape(value: str) -> str:
    s = cap(value, 1500).replace("\\", "\\\\").replace(";", "\\;").replace(",", "\\,")
    return s.replace("\r\n", "\\n").replace("\n", "\\n").replace("\r", "\\n")


def fold(line: str) -> list[str]:
    out, cur, size = [], "", 0
    for ch in line:
        n = len(ch.encode("utf-8"))
        limit = 75 if not out else 74
        if size + n > limit:
            out.append(cur)
            cur, size = "", 0
        cur += ch
        size += n
    out.append(cur)
    return [out[0]] + [" " + x for x in out[1:]]


def stamp(d) -> str:
    return d.astimezone(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def summary(f: Finding, lang: str) -> str:
    spec = load_checks().get(f.check_id)
    title = (spec.title.get(lang) or spec.title.get("en", "")) if spec else ""
    if not title:
        return cap(f.t("title", lang), 200)
    name = re.split(r"[/:]", f.resource.rstrip("/:"))[-1]
    return cap(f"{title}: {name}" if name else title, 200)


def events(run: Run, lang: str) -> list[list[str]]:
    s = strings(lang)
    out = []
    for f in run.findings:
        d = parse_ts(f.deadline)
        if not d or d <= run.now:
            continue
        parts = [f.t("what", lang), f.t("risk", lang), f"{s['fix']}: {f.t('fix', lang)}" if f.t("fix", lang) else ""]
        if owner_text(f, lang):
            parts.append(f"{s['owner_question']}: {owner_text(f, lang)}")
        parts += [f"{s['resources']}: {', '.join(f.resources[:10])}", f.uid]
        title = summary(f, lang)
        out.append([
            "BEGIN:VEVENT",
            f"UID:{escape(f.uid)}@awshealth",
            f"DTSTAMP:{stamp(run.now)}",
            f"DTSTART:{stamp(d)}",
            f"DTEND:{stamp(d + timedelta(hours=1))}",
            f"SUMMARY:{escape(title)}",
            f"DESCRIPTION:{escape(chr(10).join(p for p in parts if p))}",
            f"CATEGORIES:{escape(f.category)}",
            "BEGIN:VALARM",
            "ACTION:DISPLAY",
            f"DESCRIPTION:{escape(title)}",
            "TRIGGER:-P7D",
            "END:VALARM",
            "END:VEVENT",
        ])
    return out


def render_ics(run: Run, lang: str) -> str:
    lines = ["BEGIN:VCALENDAR", "VERSION:2.0", "PRODID:-//awshealth//awshealth " + run.version + "//EN",
             "CALSCALE:GREGORIAN", "METHOD:PUBLISH"]
    for ev in events(run, lang):
        lines += ev
    lines.append("END:VCALENDAR")
    return "".join(part + "\r\n" for line in lines for part in fold(line))


def write(run: Run, lang: str) -> Path:
    path = run.path / "deadlines.ics"
    path.write_bytes(render_ics(run, lang).encode("utf-8"))
    return path
