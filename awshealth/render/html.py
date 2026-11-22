from __future__ import annotations

import html
import json
import re
from pathlib import Path

from ..model import SEVERITIES, Finding
from .common import (
    Run,
    by_owner,
    cap,
    dated,
    days_until,
    fmt_usd,
    high_count,
    nearest_deadline,
    owner_text,
    total_usd,
    utc_text,
)
from .i18n import strings

NON_ASCII = re.compile(r"[^\x00-\x7f]")
START_HERE = 5

CSS = """
:root{--bg:#f6f6f4;--surface:#fff;--surface-2:#f0f0ed;--text:#1c2024;--muted:#5d6670;--border:#e1e1dc;
--accent:#2d5d8c;--accent-soft:#e7eef6;--critical:#9f1d1d;--high:#c2410c;--medium:#9a6700;--low:#3b6ea5;
--info:#6b7280;--ok:#2f7d4f;--radius:8px;color-scheme:light}
@media (prefers-color-scheme:dark){:root{--bg:#111315;--surface:#181b1e;--surface-2:#202428;--text:#e5e7e9;
--muted:#9aa3ab;--border:#2c3136;--accent:#82b1de;--accent-soft:#1d2a36;--critical:#f87171;--high:#fb923c;
--medium:#e3b341;--low:#82b1de;--info:#9aa3ab;--ok:#6cc28f;color-scheme:dark}}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--bg);color:var(--text);font:15px/1.55 "IBM Plex Sans",system-ui,-apple-system,
"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif}
code,pre,.mono{font-family:"IBM Plex Mono",ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:13px}
a{color:var(--accent)}
.wrap{max-width:1080px;margin:0 auto;padding:24px 16px 48px}
header.top{border-bottom:1px solid var(--border);padding-bottom:16px;margin-bottom:24px}
h1{font-size:24px;line-height:1.25;margin:0 0 12px;font-weight:600}
h2{font-size:18px;margin:40px 0 12px;font-weight:600}
h3{font-size:15px;margin:16px 0 8px;font-weight:600}
.meta{display:flex;flex-wrap:wrap;gap:6px 24px;margin:0;color:var(--muted);font-size:14px}
.meta div{display:flex;gap:6px}.meta dt{font-weight:500}.meta dd{margin:0;color:var(--text);overflow-wrap:anywhere}
.readonly{margin:12px 0 0;font-size:14px;color:var(--muted);border-left:3px solid var(--accent);padding-left:10px}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px}
.kpi{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:14px 16px}
.kpi .label{font-size:13px;color:var(--muted)}
.kpi .value{font-size:24px;font-weight:600;margin-top:4px;line-height:1.2}
.kpi .sub{font-size:13px;color:var(--muted);margin-top:4px;overflow-wrap:anywhere}
.muted{color:var(--muted)}
.intro{color:var(--muted);margin:-4px 0 12px;font-size:14px}
ol.start{list-style:none;margin:0;padding:0;display:grid;gap:8px}
.card,.item{background:var(--surface);border:1px solid var(--border);border-left:4px solid var(--info);
border-radius:var(--radius)}
.card{padding:10px 14px;display:block;color:inherit;text-decoration:none}
.card:hover,.card:focus-visible{background:var(--surface-2)}
.sev-critical{border-left-color:var(--critical)}.sev-high{border-left-color:var(--high)}
.sev-medium{border-left-color:var(--medium)}.sev-low{border-left-color:var(--low)}.sev-info{border-left-color:var(--info)}
.sev{display:inline-block;font-size:12px;font-weight:600;text-transform:uppercase;letter-spacing:.04em;
min-width:64px}
.sev.critical{color:var(--critical)}.sev.high{color:var(--high)}.sev.medium{color:var(--medium)}
.sev.low{color:var(--low)}.sev.info{color:var(--info)}
.title{font-weight:500;overflow-wrap:anywhere}
.sub{font-size:13px;color:var(--muted);overflow-wrap:anywhere}
.sub>span{display:inline-block}.sub>span+span::before{content:"\\00b7";margin:0 6px}
.filters{display:flex;flex-wrap:wrap;gap:10px 16px;align-items:center;background:var(--surface);
border:1px solid var(--border);border-radius:var(--radius);padding:12px;margin-bottom:12px}
.no-js .filters{display:none}
.chips{display:flex;flex-wrap:wrap;gap:6px}
.chip{border:1px solid var(--border);background:var(--surface-2);color:var(--muted);border-radius:999px;
padding:3px 10px;font:inherit;font-size:13px;cursor:pointer}
.chip[aria-pressed=true]{background:var(--accent-soft);color:var(--text);border-color:var(--accent)}
.filters label{font-size:13px;color:var(--muted);display:flex;align-items:center;gap:6px}
.filters select,.filters input[type=search]{font:inherit;font-size:14px;color:var(--text);background:var(--bg);
border:1px solid var(--border);border-radius:6px;padding:4px 8px;max-width:100%}
.filters input[type=search]{min-width:200px;flex:1}
.count{font-size:13px;color:var(--muted);margin:0 0 8px}
.items{display:grid;gap:8px}
.item summary{cursor:pointer;padding:10px 14px;list-style:none}
.item summary::-webkit-details-marker{display:none}
.item summary:focus-visible,.chip:focus-visible,button:focus-visible,a:focus-visible{outline:2px solid var(--accent);
outline-offset:2px}
.item[open] summary{border-bottom:1px solid var(--border)}
.body{padding:12px 14px 14px;display:grid;gap:12px}
.body h4{margin:0 0 2px;font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted);
font-weight:600}
.body p{margin:0;white-space:pre-wrap;overflow-wrap:anywhere}
.question{background:var(--accent-soft);border-radius:6px;padding:8px 10px}
.tablewrap{overflow-x:auto;border:1px solid var(--border);border-radius:6px;background:var(--surface)}
table{border-collapse:collapse;width:100%;font-size:13px}
th,td{text-align:left;padding:6px 10px;border-bottom:1px solid var(--border);vertical-align:top;
overflow-wrap:break-word}td.mono{overflow-wrap:anywhere}table.wide{min-width:620px}
th{font-weight:600;color:var(--muted);background:var(--surface-2)}
tr:last-child td{border-bottom:0}
td.num,th.num{text-align:right;white-space:nowrap}td.nowrap{white-space:nowrap}
.cmd{display:flex;gap:8px;align-items:flex-start;background:var(--surface-2);border-radius:6px;padding:6px 8px;
margin-top:4px}
.cmd code{flex:1;white-space:pre-wrap;overflow-wrap:anywhere}
.copy{font:inherit;font-size:12px;border:1px solid var(--border);background:var(--surface);color:var(--text);
border-radius:6px;padding:2px 8px;cursor:pointer;flex:none}
.no-js .copy{display:none}
ul.plain{margin:0;padding-left:18px}ul.plain li{overflow-wrap:anywhere}
.killed,.qitem{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:10px 14px;
margin-bottom:8px}
.status-dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:6px;background:var(--info)}
.st-ok{background:var(--ok)}.st-finding{background:var(--high)}.st-no_access{background:var(--critical)}
.st-not_collected{background:var(--medium)}.st-partial{background:var(--medium)}.st-error{background:var(--critical)}.st-agent{background:var(--info)}
details.group{margin-top:8px}details.group>summary{cursor:pointer;font-size:14px;padding:4px 0}
footer{margin-top:48px;padding-top:16px;border-top:1px solid var(--border);font-size:13px;color:var(--muted)}
footer p{margin:4px 0}
.empty{color:var(--muted);font-size:14px}
[hidden]{display:none!important}
@media (max-width:520px){h1{font-size:20px}.kpi .value{font-size:20px}.sev{min-width:0;margin-right:6px}
.filters input[type=search]{min-width:0;width:100%}}
@media print{.filters,.copy{display:none}.item{break-inside:avoid}}
"""

JS = """
(function(){
var T=JSON.parse(document.getElementById('awshealth-i18n').textContent);
document.documentElement.className='js';
function fmt(s,n,t){return s.replace('{n}',n).replace('{total}',t);}
document.querySelectorAll('time[datetime]').forEach(function(el){
var d=new Date(el.getAttribute('datetime'));if(isNaN(d))return;
el.title=el.textContent;
var o=el.dataset.date?{dateStyle:'medium'}:{dateStyle:'medium',timeStyle:'short'};
try{el.textContent=d.toLocaleString(T.lang,o);}catch(e){}
});
document.querySelectorAll('button.copy').forEach(function(b){
b.addEventListener('click',function(){
var text=b.parentNode.querySelector('code').textContent;
function done(){b.textContent=T.copied;setTimeout(function(){b.textContent=T.copy;},1500);}
if(navigator.clipboard&&window.isSecureContext){navigator.clipboard.writeText(text).then(done);}
else{var ta=document.createElement('textarea');ta.value=text;document.body.appendChild(ta);ta.select();
try{document.execCommand('copy');done();}catch(e){}document.body.removeChild(ta);}
});
});
function openTarget(){var id=location.hash.slice(1);if(!id)return;var el=document.getElementById(id);
if(el&&el.tagName==='DETAILS'){el.hidden=false;el.open=true;}}
window.addEventListener('hashchange',openTarget);openTarget();
var items=[].slice.call(document.querySelectorAll('.items .item'));
var chips=[].slice.call(document.querySelectorAll('.chip[data-sev]'));
var src=document.getElementById('f-source'),reg=document.getElementById('f-region'),
q=document.getElementById('f-q'),cost=document.getElementById('f-cost'),
cnt=document.getElementById('f-count'),none=document.getElementById('f-none');
if(!q)return;
function apply(){
var sevs=chips.filter(function(c){return c.getAttribute('aria-pressed')==='true';})
.map(function(c){return c.dataset.sev;});
var term=(q.value||'').toLowerCase().trim(),shown=0;
items.forEach(function(it){
var ok=sevs.indexOf(it.dataset.sev)>=0&&(!src.value||it.dataset.source===src.value)&&
(!reg.value||it.dataset.region===reg.value)&&(!cost.checked||it.dataset.cost==='1')&&
(!term||it.dataset.q.indexOf(term)>=0);
it.hidden=!ok;if(ok)shown++;
});
cnt.textContent=fmt(T.showing,shown,items.length);none.hidden=shown>0;
}
chips.forEach(function(c){c.addEventListener('click',function(){
c.setAttribute('aria-pressed',c.getAttribute('aria-pressed')==='true'?'false':'true');apply();});});
[src,reg,cost].forEach(function(el){el.addEventListener('change',apply);});
q.addEventListener('input',apply);
apply();
})();
"""


def e(value, n: int = 2000) -> str:
    return html.escape(cap(value, n), quote=True)


def to_ascii(doc: str) -> str:
    return NON_ASCII.sub(lambda m: f"&#x{ord(m.group()):x};", doc)


def script_json(obj) -> str:
    s = json.dumps(obj, ensure_ascii=True)
    return s.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")


def anchor(f: Finding) -> str:
    return "f-" + re.sub(r"[^A-Za-z0-9_-]", "-", f.uid)


def time_el(ts: str, date_only: bool = False) -> str:
    extra = ' data-date="1"' if date_only else ""
    return f'<time datetime="{e(ts, 64)}"{extra}>{e(utc_text(ts, not date_only))}</time>'


def rel_el(ts: str, run: Run, s: dict) -> str:
    n = days_until(ts, run.now)
    if n is None:
        return ""
    text = s["today"] if n == 0 else (s["in_days"] if n > 0 else s["days_ago"]).replace("{n}", str(abs(n)))
    return f'<span data-rel="{e(ts, 64)}">{e(text)}</span>'


def sev_label(sev: str, s: dict) -> str:
    return f'<span class="sev {e(sev, 16)}">{e(s.get("sev_" + sev, sev))}</span>'


def sub_line(f: Finding, run: Run, s: dict, lang: str) -> str:
    parts = [f'<span class="mono">{e(f.check_id, 120)}</span>', f"<span>{e(f.region, 40)}</span>"]
    if f.source != "awshealth":
        parts.append(f"<span>{e(f.source, 60)}</span>")
    if f.monthly_usd:
        parts.append(f"<span>{e(fmt_usd(f.monthly_usd, lang))}{e(s['per_month'])}</span>")
    if f.deadline:
        parts.append(f"<span>{e(s['deadline'])} {time_el(f.deadline, True)}</span>")
    return '<div class="sub">' + "".join(parts) + "</div>"


def section(title: str, sid: str, body: str, intro: str = "") -> str:
    intro_html = f'<p class="intro">{e(intro)}</p>' if intro else ""
    return f'<section id="{sid}"><h2>{e(title)}</h2>{intro_html}{body}</section>'


def header(run: Run, s: dict) -> str:
    m = run.meta
    rows = [(s["account"], e(m.get("account_id", ""), 40)),
            (s["regions"], e(", ".join(m.get("regions") or []), 600)),
            (s["collected_at"], time_el(m["collected_at"]) if m.get("collected_at") else e(s["none"])),
            (s["tool_version"], e(run.version, 40))]
    meta = "".join(f"<div><dt>{e(k)}</dt><dd>{v}</dd></div>" for k, v in rows)
    return (f'<header class="top"><h1>{e(s["report_title"])}</h1><dl class="meta">{meta}</dl>'
            f'<p class="readonly">{e(s["read_only"])}</p></header>')


def kpis(run: Run, s: dict, lang: str) -> str:
    near = nearest_deadline(run)
    if near:
        deadline = (f'<div class="value">{time_el(near.deadline, True)}</div>'
                    f'<div class="sub">{rel_el(near.deadline, run, s)} &middot; '
                    f'<a href="#{anchor(near)}">{e(near.t("title", lang), 90)}</a></div>')
    else:
        deadline = f'<div class="value">{e(s["kpi_deadline_none"])}</div>'
    cov = run.coverage
    cards = [
        (s["kpi_deadline"], deadline),
        (s["kpi_usd"], f'<div class="value">{e(fmt_usd(total_usd(run), lang))}</div>'
                       f'<div class="sub">{e(s["kpi_usd_note"])}</div>'),
        (s["kpi_high"], f'<div class="value">{high_count(run)}</div>'),
        (s["kpi_coverage"], f'<div class="value">{cov["checked"]}/{cov["total"]}</div>'
                            f'<div class="sub">{e(s["status_agent"])}: {cov["counts"]["agent"]}</div>'),
    ]
    body = "".join(f'<div class="kpi"><div class="label">{e(k)}</div>{v}</div>' for k, v in cards)
    return f'<section class="kpis" aria-label="KPIs">{body}</section>'


def start_here(run: Run, s: dict, lang: str) -> str:
    top = run.findings[:START_HERE]
    if not top:
        return section(s["start_here"], "start", f'<p class="empty">{e(s["start_here_none"])}</p>')
    cards = "".join(
        f'<li><a class="card sev-{e(f.severity, 16)}" href="#{anchor(f)}">{sev_label(f.severity, s)} '
        f'<span class="title">{e(f.t("title", lang), 300)}</span>{sub_line(f, run, s, lang)}</a></li>'
        for f in top)
    return section(s["start_here"], "start", f'<ol class="start">{cards}</ol>')


def claim_value(v) -> str:
    return v if isinstance(v, str) else json.dumps(v, default=str, ensure_ascii=False)


def claims_table(f: Finding, s: dict) -> str:
    if not f.claims:
        return ""
    rows = "".join(
        f'<tr><td class="mono">{e(c.source, 200)}</td><td class="mono">{e(c.path, 300)}</td>'
        f'<td class="mono">{e(claim_value(c.value), 500)}</td></tr>'
        for c in f.claims[:50])
    head = f'<tr><th>{e(s["claim_source"])}</th><th>{e(s["claim_path"])}</th><th>{e(s["claim_value"])}</th></tr>'
    return f'<div><h4>{e(s["claims"])}</h4><div class="tablewrap"><table>{head}{rows}</table></div></div>'


def item(f: Finding, run: Run, s: dict, lang: str) -> str:
    blocks = []
    for key in ("what", "risk"):
        if f.t(key, lang):
            blocks.append(f'<div><h4>{e(s[key])}</h4><p>{e(f.t(key, lang))}</p></div>')
    if f.monthly_usd:
        calc = f"<p class=\"mono\">{e(f.usd_calc, 600)}</p>" if f.usd_calc else ""
        blocks.append(f'<div><h4>{e(s["cost"])}</h4><p>{e(fmt_usd(f.monthly_usd, lang))}{e(s["per_month"])}</p>'
                      f'{calc}</div>')
    if f.t("fix", lang):
        blocks.append(f'<div><h4>{e(s["fix"])}</h4><p>{e(f.t("fix", lang))}</p></div>')
    if owner_text(f, lang):
        blocks.append(f'<div class="question"><h4>{e(s["owner_question"])}</h4><p>{e(owner_text(f, lang))}</p></div>')
    if f.notes:
        notes = "".join(f"<li>{e(n, 600)}</li>" for n in f.notes[:20])
        blocks.append(f'<div><h4>{e(s["notes"])}</h4><ul class="plain">{notes}</ul></div>')
    blocks.append(claims_table(f, s))
    if f.verify:
        cmds = "".join(f'<div class="cmd"><code>{e(c, 1000)}</code>'
                       f'<button class="copy" type="button">{e(s["copy"])}</button></div>' for c in f.verify[:5])
        blocks.append(f'<div><h4>{e(s["verify"])}</h4>{cmds}</div>')
    res = "".join(f'<li class="mono">{e(r, 512)}</li>' for r in f.resources[:50])
    blocks.append(f'<div><h4>{e(s["resources"])}</h4><ul class="plain">{res}</ul></div>')
    search = " ".join([cap(f.t("title", lang), 300), f.resource, f.check_id, f.region, f.source,
                       *f.resources[:20]]).lower()
    attrs = (f'id="{anchor(f)}" class="item sev-{e(f.severity, 16)}" data-sev="{e(f.severity, 16)}" '
             f'data-source="{e(f.source, 60)}" data-region="{e(f.region, 40)}" '
             f'data-cost="{1 if f.monthly_usd else 0}" data-q="{e(search, 3000)}"')
    return (f'<details {attrs}><summary>{sev_label(f.severity, s)} <span class="title">'
            f'{e(f.t("title", lang), 300)}</span>{sub_line(f, run, s, lang)}</summary>'
            f'<div class="body">{"".join(blocks)}</div></details>')


def options(values: list[str], s: dict, n: int) -> str:
    opts = [f'<option value="">{e(s["filter_all"])}</option>']
    opts += [f'<option value="{e(v, n)}">{e(v, n)}</option>' for v in values]
    return "".join(opts)


def inventory(run: Run, s: dict, lang: str) -> str:
    if not run.findings:
        return section(s["inventory"], "inventory", f'<p class="empty">{e(s["start_here_none"])}</p>')
    present = [sev for sev in SEVERITIES if any(f.severity == sev for f in run.findings)]
    chips = "".join(f'<button type="button" class="chip" data-sev="{sev}" aria-pressed="true">'
                    f'{e(s["sev_" + sev])}</button>' for sev in present)
    filters = (
        f'<div class="filters" role="search"><div class="chips" role="group" aria-label="{e(s["filter_severity"])}">'
        f'{chips}</div>'
        f'<label>{e(s["filter_source"])} <select id="f-source">{options(run.sources, s, 60)}</select></label>'
        f'<label>{e(s["filter_region"])} <select id="f-region">{options(run.regions, s, 40)}</select></label>'
        f'<label>{e(s["filter_search"])} <input type="search" id="f-q" '
        f'placeholder="{e(s["filter_search_placeholder"])}"></label>'
        f'<label><input type="checkbox" id="f-cost"> {e(s["filter_cost"])}</label></div>'
        f'<p class="count" id="f-count" aria-live="polite"></p>'
        f'<p class="empty" id="f-none" hidden>{e(s["no_match"])}</p>'
    )
    items = "".join(item(f, run, s, lang) for f in run.findings)
    return section(s["inventory"], "inventory", f'{filters}<div class="items">{items}</div>')


def killed(run: Run, s: dict, lang: str) -> str:
    if not run.killed:
        return section(s["killed"], "killed", f'<p class="empty">{e(s["killed_none"])}</p>', s["killed_intro"])
    out = []
    for k in run.killed:
        ev = "".join(f"<li>{e(x, 600)}</li>" for x in k.evidence[:20])
        out.append(f'<div class="killed">{sev_label(k.finding.severity, s)} <span class="title">'
                   f'{e(k.finding.t("title", lang), 300)}</span>'
                   f'<div class="sub"><span class="mono">{e(k.finding.uid, 160)}</span>'
                   f'<span class="mono">{e(k.finding.resource, 300)}</span></div>'
                   f'<p><strong>{e(s["reason"])}:</strong> {e(k.reason, 1000)}</p>'
                   f'<h4 class="muted">{e(s["evidence"])}</h4><ul class="plain">{ev}</ul></div>')
    return section(s["killed"], "killed", "".join(out), s["killed_intro"])


def questions(run: Run, s: dict, lang: str) -> str:
    if not run.questions:
        return section(s["questions"], "questions", f'<p class="empty">{e(s["questions_none"])}</p>')
    out = []
    for owner, group in by_owner(run, s["unassigned"]):
        out.append(f'<h3>{e(s["owner"])}: {e(owner, 120)}</h3>')
        for f in group:
            out.append(f'<div class="qitem"><p>{e(owner_text(f, lang), 1000)}</p>'
                       f'<div class="sub"><a href="#{anchor(f)}">{e(f.t("title", lang), 200)}</a></div></div>')
    return section(s["questions"], "questions", "".join(out), s["questions_intro"])


def deadlines(run: Run, s: dict, lang: str) -> str:
    rows = []
    for f in dated(run):
        n = days_until(f.deadline, run.now)
        when = rel_el(f.deadline, run, s) if n is None or n >= 0 else e(s["passed"])
        usd = e(fmt_usd(f.monthly_usd, lang)) + e(s["per_month"]) if f.monthly_usd else ""
        rows.append(f'<tr><td class="nowrap">{time_el(f.deadline)}</td><td class="nowrap">{when}</td>'
                    f'<td>{sev_label(f.severity, s)}</td>'
                    f'<td><a href="#{anchor(f)}">{e(f.t("title", lang), 200)}</a></td><td class="num">{usd}</td></tr>')
    if not rows:
        return section(s["deadlines"], "deadlines", f'<p class="empty">{e(s["deadlines_none"])}</p>')
    head = (f'<tr><th>{e(s["deadline"])}</th><th>{e(s["when"])}</th><th>{e(s["severity"])}</th>'
            f'<th>{e(s["finding"])}</th><th class="num">{e(s["cost"])}</th></tr>')
    table = f'<div class="tablewrap"><table class="wide">{head}{"".join(rows)}</table></div>'
    return section(s["deadlines"], "deadlines", table)


def coverage(run: Run, s: dict) -> str:
    cov = run.coverage
    rows = "".join(f'<tr><td><span class="status-dot st-{st}"></span>{e(s["status_" + st])}</td>'
                   f'<td class="num">{n}</td></tr>' for st, n in cov["counts"].items())
    out = [f'<div class="tablewrap"><table><tr><th>{e(s["status"])}</th><th class="num">{e(s["count"])}</th></tr>'
           f'{rows}</table></div>']
    for st in cov["counts"]:
        entries = [x for x in cov["entries"] if x["status"] == st]
        if not entries:
            continue
        lines = "".join(f'<tr><td class="mono">{e(x["id"], 120)}</td><td>{e(x["title"], 300)}</td>'
                        f'<td class="mono">{e(", ".join(x["checks"]) or "-", 300)}</td></tr>' for x in entries)
        out.append(f'<details class="group"><summary>{e(s["status_" + st])} ({len(entries)})</summary>'
                   f'<div class="tablewrap"><table><tr><th>id</th><th>{e(s["finding"])}</th>'
                   f'<th>{e(s["covered_by"])}</th></tr>{lines}</table></div></details>')
    out.append(f'<h3>{e(s["api_problems"])}</h3>')
    if run.api_problems:
        lines = "".join(f'<tr><td class="mono">{e(p["call"], 200)}</td><td>{e(p["region"], 40)}</td>'
                        f'<td>{e(p["status"], 20)}</td><td class="mono">{e(p["error"], 300)}</td></tr>'
                        for p in run.api_problems[:500])
        out.append(f'<div class="tablewrap"><table><tr><th>{e(s["call"])}</th><th>{e(s["region"])}</th>'
                   f'<th>{e(s["status"])}</th><th></th></tr>{lines}</table></div>')
    else:
        out.append(f'<p class="empty">{e(s["api_problems_none"])}</p>')
    intro = s["coverage_intro"].replace("{total}", str(cov["total"]))
    return section(s["coverage"], "coverage", "".join(out), intro)


def footer(run: Run, s: dict) -> str:
    if run.calls is None:
        ledger = e(s["footer_no_ledger"])
    else:
        ledger = e(s["footer_calls"].replace("{n}", str(run.calls))) + " " + e(
            s["footer_blocked"].replace("{n}", str(run.blocked)))
    return (f'<footer><p>{ledger}</p><p>{e(s["read_only"])}</p>'
            f'<p>{e(s["generated_by"].replace("{v}", run.version))}</p></footer>')


def render_html(run: Run, lang: str) -> str:
    s = strings(lang)
    t = {k: s[k] for k in ("copy", "copied", "showing", "in_days", "days_ago", "today")}
    t["lang"] = lang
    body = "".join([
        header(run, s), kpis(run, s, lang), start_here(run, s, lang), inventory(run, s, lang), killed(run, s, lang),
        questions(run, s, lang), deadlines(run, s, lang), coverage(run, s), footer(run, s),
    ])
    title = f'{s["report_title"]} {run.meta.get("account_id", "")}'.strip()
    doc = (
        f'<!doctype html><html lang="{e(lang, 8)}" class="no-js"><head><meta charset="utf-8">'
        f'<meta name="viewport" content="width=device-width,initial-scale=1">'
        f'<meta name="referrer" content="no-referrer">'
        f"<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; "
        f"script-src 'unsafe-inline'; img-src data:\">"
        f'<title>{e(title, 120)}</title><style>{CSS}</style></head><body><main class="wrap">{body}</main>'
        f'<script type="application/json" id="awshealth-i18n">{script_json(t)}</script>'
        f'<script>{JS}</script></body></html>\n'
    )
    return to_ascii(doc)


def write(run: Run, lang: str) -> Path:
    path = run.path / "report.html"
    path.write_text(render_html(run, lang), encoding="ascii")
    return path
