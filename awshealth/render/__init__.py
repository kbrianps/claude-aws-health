from __future__ import annotations

from datetime import datetime
from pathlib import Path

from . import html, ics, markdown, ocsf
from .common import load_run


def render_all(run_dir: Path, lang: str = "en", *, now: datetime | None = None) -> list[Path]:
    run = load_run(Path(run_dir), now=now)
    md_paths = markdown.write(run, lang)
    return [html.write(run, lang), md_paths[0], ics.write(run, lang), *md_paths[1:], ocsf.write(run)]
