"""Cycle report (DR-01, DR-02, DR-17, DR-21): results.json, RESULTS.md, CSV tables, EXHIBIT.html, paper LaTeX preview.

Every value in results.json carries its source (cycle stage-log record and the stage's sealed output hash),
so the paper's numbers trace back to retained records. Pilot cycles are reported in pilot mode: the paper
LaTeX generated from them is stamped PILOT DATA. Only a published campaign cycle feeds the paper itself.
"""
from __future__ import annotations

import csv
import html
import json
from pathlib import Path
from typing import Any

from ..cycles import Cycle
from ..hashing import sha256_file
from ..paths import protocol_dir
from . import exhibit as ex
from . import paper_tex


def _tex(s: Any) -> str:
    out = str(s)
    for a, b in (("\\", r"\textbackslash{}"), ("_", r"\_"), ("%", r"\%"), ("&", r"\&"), ("#", r"\#"), ("$", r"\$"),
                 ("→", r"$\rightarrow$"), ("Δ", r"$\Delta$")):
        out = out.replace(a, b)
    return out


def _src(cycle: Cycle, n: int) -> str:
    st = cycle.data["stages"][str(n)]
    return f"records/cycles/{cycle.id}/stage-log.jsonl#stage={n};outputs={str(st.get('outputs_manifest_sha256'))[:16]}"


def results_json(cycle: Cycle) -> dict[str, Any]:
    s = {n: cycle.data["stages"][str(n)].get("outcome", {}) for n in range(1, 5)}
    m = lambda v, n: {"value": _tex(v), "source": _src(cycle, n)}  # noqa: E731
    pair = s[4].get("selected_pair")
    status = (f"Results from cycle {cycle.id} ({cycle.data['mode']}). All four stages completed; every value "
              f"below is generated from the cycle's retained records.")
    abstract = (f"Across {s[1].get('repoaudit_runs')} RepoAudit executions ({s[1].get('repoaudit_green')} GREEN), "
                f"the three-GREEN case was {_tex(s[4].get('three_green_case', 'unattained'))}; oracle agreement "
                f"{s[4].get('oracle_agreement')}. ProofWeave made evidence queryable for posture calculation in a median "
                f"{s[2].get('median_ms')} ms (maximum {s[2].get('max_ms')} ms) against the \\PWBudget{{}} reference threshold, "
                f"with threshold crossing: {_tex(s[3].get('threshold_crossing'))} up to {s[3].get('largest_volume')} records.")
    mode = "campaign" if cycle.data["mode"] == "campaign" else "pilot"
    out = {
        "mode": mode, "cycle": cycle.id,
        "freeze_manifest_sha256": s[2].get("corpus_sha256") if mode == "campaign" else None,
        "macros": {
            "PWRunTotal": m(s[1].get("repoaudit_runs"), 1), "PWRunGreen": m(s[1].get("repoaudit_green"), 1),
            "PWRunIncomplete": m(s[1].get("repoaudit_failed"), 1),
            "PWRunPathObservable": m(s[4].get("runs_path_observable"), 4),
            "PWEligiblePairs": m(s[4].get("eligible_pairs"), 4), "PWDivergentPairs": m(s[4].get("qualifying_pairs"), 4),
            "PWSelectedPair": m(", ".join(pair) if pair else "unattained", 4),
            "PWCorpusRecords": m(s[2].get("records"), 2),
            "PWCorpusHash": m(f"{cycle.id} / {str(s[2].get('corpus_sha256'))[:16]}", 2),
            "PWMaximumScale": m(f"{max(s[3]['volumes'][str(s[3]['largest_volume'])]['actual'])} records", 3),
            "PWMaximumReady": m(f"{s[3].get('max_ready_ms_at_largest')} ms", 3),
            "PWBudgetBoundary": m(s[3].get("threshold_crossing"), 3),
            "PWOracleAgreement": m(s[4].get("oracle_agreement"), 4),
            "PWUnsupportedProceed": m(s[4].get("unsupported_proceed"), 4),
            "PWReplayAgreement": m(s[4].get("replay_agreement"), 4),
            "PWResultStatus": {"value": _tex(status), "source": _src(cycle, 4)},
            "PWAbstractResults": {"value": abstract, "source": _src(cycle, 4)},
        },
        "timing_rows": {}, "assurance_rows": {},
    }
    for v, r in s[3]["volumes"].items():
        out["timing_rows"][v] = {"actual": _tex(", ".join(map(str, sorted(set(r["actual"]))))),
                                 "repetitions": str(r["repetitions"]), "median": f"{r['median_ms']} ms",
                                 "maximum": f"{r['max_ms']} ms",
                                 "failures_threshold": f"{r['not_ready']} not ready; {r['exceedances']} above \\PWBudget{{}}"}
    for vid, r in s[4]["views"].items():
        if not r["attainable"]:
            out["assurance_rows"][vid] = {k: "unattained" for k in ("verdict_only", "oracle", "observed")}
            out["assurance_rows"][vid]["trace"] = _tex(r["note"])
        else:
            out["assurance_rows"][vid] = {
                "verdict_only": r["verdict_only"], "oracle": f"{r['oracle']} / {r['oracle_action']}",
                "observed": f"{r['observed']} / {r['action']}",
                "trace": _tex("missing " + ", ".join(r["missing"]) if r["missing"] else
                              ("failed " + ", ".join(r["failed"]) if r["failed"] else "all requirements supported"))}
    return out


def _md_exhibit(x: dict[str, Any]) -> list[str]:
    c, n = x["case"], x["narrative"]
    L = ["## Worked example: three GREENs, not enough coverage", "",
         f"*Illustrative, from cycle `{x['cycle']}` ({x['mode']}). It explains the results above and does not replace them.*",
         "", "<details><summary>Glossary</summary>", ""]
    L += [f"- **{g['term']}**: {g['meaning']}" for g in x["glossary"]]
    pw = x["pathways"]
    L += ["", "</details>", "", "### In short", "", n["summary"], "",
          "### Same code, same bug type, different pathways", "", pw["summary"], "",
          "| Pathway | " + " | ".join(f"`{r}`" for r in pw["runs"]) + " |", "|---|" + "---|" * len(pw["runs"])]
    L += [f"| {row['plain']} | " + " | ".join({"followed": "✓", "validated": "✓ validated", None: "✗"}[row["cells"][r]]
                                               for r in pw["runs"]) + " |" for row in pw["rows"]]
    L += ["", "| Runs | Relation | Both GREEN | Shared pathways | Similarity |", "|---|---|---|---|---|"]
    L += [f"| `{p['runs'][0]}` · `{p['runs'][1]}` | {p['relation']} | {'yes' if p['both_green'] else 'no'} | "
          f"{p['shared']} of {p['union']} | {'' if p['similarity'] is None else format(p['similarity'], '.0%')} |"
          for p in pw["pairs"]]
    L += ["",
          f"| Gateway reading | Decision |", "|---|---|",
          f"| Verdicts only (\"green means go\") | **{c['verdict_only']}** |",
          f"| ProofWeave + TAIP (coverage of the required set) | **{c['taip']} → {c['gateway']}** |",
          f"| Independent oracle | {c['oracle']} ({'agrees' if c['oracle_agrees'] else 'DISAGREES'}) |", ""]
    if n["missing"]:
        L += ["### What the missing requirements mean", ""]
        L += [f"- **{m['id']}: {m['requirement']}.** {m['explanation']}" for m in n["missing"]]
        L += ["", n["missing_close"], ""]
    L += ["### Each run, in plain words", ""]
    L += [f"- **`{r['run']}`**: {r['text']} *{r['role']}*" for r in n["runs"]]
    L += ["", "### What each run actually examined", "",
          "| Requirement | " + " | ".join(f"`{col}`" for col in x["columns"]) + " |",
          "|---|" + "---|" * len(x["columns"])]
    for m in x["matrix"]:
        L.append(f"| {m['id']} {m['plain']} | " + " | ".join("✓" if m["cells"][col] else "✗" for col in x["columns"]) + " |")
    ct = x["contrast"]
    if ct:
        L += ["", f"### Contrast: {ct['item']}", "", ct.get("story", ""), ""]
        if ct["excerpt"]:
            L += [f"**`{ct['covering_run']}`: RepoAudit's own record** ({ct['excerpt']['location']}; ledger record "
                  f"`{ct['excerpt']['ledger_record'][:16]}…`):", "", "```", ct["excerpt"]["text"], "```", ""]
        if ct["missing_run_summary"]:
            L += [f"**`{ct['missing_run']}`:** {ct['missing_run_summary']}."]
        L += ["", f"*Selection rule: {x['selection_rule']}.*"]
    return L


def _html(x: dict[str, Any], title: str) -> str:
    e = html.escape
    c, ct, n = x["case"], x["contrast"], x["narrative"]
    case_runs = [r["run"] for r in c["runs"]]
    gloss = "".join(f"<dt>{e(g['term'])}</dt><dd>{e(g['meaning'])}</dd>" for g in x["glossary"])
    cards = "".join(
        f"<div class='card'><div class='k'>{e(r['control'])}</div><div class='v'>{e(r['run'])}</div>"
        f"<div class='m'>{e(str(r['model'] or 'fixed rules'))}{' · temperature ' + e(str(r['temperature'])) if r['temperature'] is not None else ''}</div>"
        f"<div class='badge {'g' if r['green'] else 'r'}'>{'GREEN' if r['green'] else 'not GREEN'}</div></div>"
        for r in c["runs"])
    missing = ""
    if n["missing"]:
        missing = ("<h2>What the missing requirements mean</h2><ol class='miss'>" +
                   "".join(f"<li><div class='mh'><span class='id'>{e(m['id'])}</span>{e(m['requirement'])}</div>"
                           f"<p>{e(m['explanation'])}</p></li>" for m in n["missing"]) +
                   f"</ol><p class='close'>{e(n['missing_close'])}</p>")
    stories = "".join(
        f"<div class='run {'in' if r['run'] in case_runs else 'out'}'><div class='rh'><span class='v'>{e(r['run'])}</span>"
        f"<span class='badge {'g' if r['green'] else 'r'}'>{'GREEN' if r['green'] else 'not GREEN'}</span>"
        f"<span class='m'>{e(r['model'])}</span></div><p>{e(r['text'])}</p><p class='role'>{e(r['role'])}</p></div>"
        for r in n["runs"])
    head = "".join(f"<th scope='col' class='{'in' if col in case_runs else ''}'>{e(col)}"
                   f"{'<br><span class=tag>in view</span>' if col in case_runs else ''}</th>" for col in x["columns"])
    rows = "".join(
        f"<tr class='{'' if m['in_case'] else 'gap'}'><th scope='row'>{e(m['id'])}</th><td class='req'>{e(m['plain'])}</td>" +
        "".join(f"<td class='{'y' if m['cells'][col] else 'n'}{' in' if col in case_runs else ''}' "
                f"title='{m['cells'][col]} witness record(s)'>{'✓' if m['cells'][col] else '✗'}</td>" for col in x["columns"]) +
        "</tr>" for m in x["matrix"])
    contrast = ""
    if ct:
        exc = (f"<h3>{e(ct['covering_run'] or '')}: RepoAudit's own record of the question</h3><p class='m'>{e(ct['excerpt']['location'])}</p>"
               f"<pre>{e(ct['excerpt']['text'])}</pre>") if ct["excerpt"] else ""
        contrast = (f"<section><h2>Contrast: one requirement, two runs</h2><p class='lead'>{e(ct.get('story', ''))}</p>"
                    f"{exc}<h3>{e(ct['missing_run'] or '')}</h3><p>{e(ct['missing_run_summary'] or '')}.</p>"
                    f"<p class='m'>Selection rule: {e(x['selection_rule'])}.</p></section>")
    pw = x["pathways"]
    mark = {"followed": ("y", "✓"), "validated": ("y", "✓✓"), None: ("n", "✗")}
    pw_head = "".join(f"<th scope='col'>{e(r)}</th>" for r in pw["runs"])
    pw_rows = "".join(
        f"<tr><td class='req'>{e(row['plain'])}</td>" +
        "".join(f"<td class='{mark[row['cells'][r]][0]}' title='{e(str(row['cells'][r] or 'not explored'))}'>"
                f"{mark[row['cells'][r]][1]}</td>" for r in pw["runs"]) + "</tr>" for row in pw["rows"])
    pw_pairs = "".join(
        f"<tr><td class='v'>{e(p['runs'][0])}<br>{e(p['runs'][1])}</td><td>{e(p['relation'])}</td>"
        f"<td>{'GREEN · GREEN' if p['both_green'] else 'not both GREEN'}</td><td>{p['shared']} of {p['union']}</td>"
        f"<td>{'' if p['similarity'] is None else format(p['similarity'], '.0%')}</td></tr>" for p in pw["pairs"])
    pathways_html = (f"<h2>Same code, same bug type, different pathways</h2><p class='lead'>{e(pw['summary'])}</p>"
                     f"<p class='m'>A pathway is one step RepoAudit took while following a None: from the function "
                     f"it came from into the next function, which it then analysed. ✓ = the run took this step; "
                     f"✓✓ = it also asked its path validator about it; ✗ = it never took it.</p>"
                     f"<div class='tw'><table><thead><tr><th scope='col'>Pathway</th>{pw_head}</tr></thead>"
                     f"<tbody>{pw_rows}</tbody></table></div>"
                     f"<h3>Pairs of runs</h3><div class='tw'><table><thead><tr><th scope='col'>Runs</th>"
                     f"<th scope='col'>Relation</th><th scope='col'>Verdicts</th><th scope='col'>Shared pathways</th>"
                     f"<th scope='col'>Similarity</th></tr></thead><tbody>{pw_pairs}</tbody></table></div>"
                     if pw["runs"] else "")
    go = lambda a: "go" if a == "PROCEED" else "stop"  # noqa: E731
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{e(title)}</title><style>
:root{{--bg:#f6f7f9;--fg:#17202a;--mut:#4b5563;--card:#fff;--line:#dde1e6;--g:#0f766e;--gb:#ecfdf5;--r:#b91c1c;--rb:#fef2f2;--acc:#1d4ed8;--hl:#eef2ff}}
@media (prefers-color-scheme:dark){{:root{{--bg:#111418;--fg:#e5e7eb;--mut:#9ca3af;--card:#1a1f26;--line:#2d333b;--g:#5eead4;--gb:#0f2e2a;--r:#fca5a5;--rb:#3a1a1a;--acc:#93c5fd;--hl:#1e2433}}}}
*{{box-sizing:border-box}} body{{margin:0;background:var(--bg);color:var(--fg);font:16px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif}}
main{{max-width:1180px;margin:0 auto;padding:28px 16px 64px}} h1{{font-size:28px;margin:0 0 4px}} h2{{font-size:20px;margin:36px 0 10px}} h3{{font-size:16px;margin:20px 0 6px}}
p{{margin:6px 0}} .m{{color:var(--mut);font-size:14px}} .lead{{font-size:17px;max-width:75ch}}
details.gl{{background:var(--card);border:1px solid var(--line);border-radius:10px;margin:18px 0;padding:0 16px}}
details.gl summary{{cursor:pointer;font-weight:600;padding:12px 0}} details.gl dl{{margin:0 0 14px;display:grid;grid-template-columns:minmax(150px,220px) 1fr;gap:8px 18px}}
details.gl dt{{font-weight:600}} details.gl dd{{margin:0;color:var(--fg)}}
@media (max-width:640px){{details.gl dl{{grid-template-columns:1fr}} details.gl dd{{margin-bottom:8px}}}}
.cards{{display:flex;flex-wrap:wrap;gap:12px}} .card{{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px;flex:1 1 220px}}
.k{{font-size:12px;color:var(--mut);text-transform:uppercase;letter-spacing:.05em}} .v{{font-family:ui-monospace,monospace;font-size:15px;overflow-wrap:anywhere}}
.badge{{display:inline-block;margin:6px 0;padding:2px 10px;border-radius:999px;font-weight:600;font-size:13px}} .badge.g{{color:var(--g);background:var(--gb)}} .badge.r{{color:var(--r);background:var(--rb)}}
.dec{{display:flex;flex-wrap:wrap;gap:12px;margin-top:12px}} .dec>div{{flex:1 1 300px;background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px}}
.big{{font-size:24px;font-weight:700}} .go{{color:var(--g)}} .stop{{color:var(--r)}}
ol.miss{{list-style:none;padding:0;margin:0;display:grid;gap:10px}} ol.miss li{{background:var(--card);border:1px solid var(--line);border-left:4px solid var(--r);border-radius:10px;padding:12px 14px}}
.mh{{font-weight:600}} .id{{font-family:ui-monospace,monospace;color:var(--r);margin-right:10px}} .close{{font-weight:600;margin-top:14px;max-width:75ch}}
.run{{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 14px;margin-bottom:10px}} .run.in{{border-left:4px solid var(--acc)}}
.rh{{display:flex;flex-wrap:wrap;align-items:center;gap:6px 12px}} .role{{color:var(--mut);font-size:14px;font-style:italic}}
.tw{{overflow-x:auto;border:1px solid var(--line);border-radius:10px;background:var(--card)}} table{{border-collapse:collapse;width:100%;font-size:14px}}
th,td{{padding:6px 10px;border-bottom:1px solid var(--line);text-align:left;white-space:nowrap}} td.req{{white-space:normal;min-width:260px}}
th.in,td.in{{background:var(--hl)}} .tag{{font-size:11px;font-weight:600;color:var(--acc);text-transform:uppercase}}
tr.gap th[scope=row]{{color:var(--r)}} td.y{{color:var(--g);text-align:center;font-weight:700}} td.n{{color:var(--r);text-align:center}}
pre{{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px;overflow-x:auto;font-size:13px}}
</style></head><body><main>
<h1>Three GREENs, not enough coverage</h1><p class="m">Cycle {e(x['cycle'])} ({e(x['mode'])}). Illustrative example from retained records; it explains the reported results and does not replace them.</p>
<details class="gl"><summary>Glossary: what the terms on this page mean</summary><dl>{gloss}</dl></details>
<h2>In short</h2><p class="lead">{e(n['summary'])}</p>
{pathways_html}
<h2>The verdicts ({e(str(c['view']))})</h2><div class="cards">{cards}</div>
<div class="dec"><div><div class="k">Verdicts only ("green means go")</div><div class="big {go(c['verdict_only'])}">{e(str(c['verdict_only']))}</div></div>
<div><div class="k">ProofWeave + TAIP: coverage of the required set</div><div class="big {go(c['gateway'])}">{e(str(c['taip']))} → {e(str(c['gateway']))}</div>
<div class="m">Missing: {e(', '.join(c['missing'] or []) or 'none')} · independent oracle {e(str(c['oracle']))} ({'agrees' if c['oracle_agrees'] else 'disagrees'})</div></div></div>
{missing}
<h2>Each run, in plain words</h2>{stories}
<h2>What each run actually examined</h2><p class="m">✓ = a witness in the ledger shows the run covered the requirement (hover for the count); ✗ = no evidence it did. Highlighted columns are the runs in the view; red row IDs are requirements the view does not cover.</p>
<div class="tw"><table><thead><tr><th scope="col">Item</th><th scope="col">Requirement</th>{head}</tr></thead><tbody>{rows}</tbody></table></div>
{contrast}</main></body></html>"""


def write(cycle: Cycle, out: Path | None = None, item_id: str | None = None, runs: list[str] | None = None) -> Path:
    if cycle.data["status"] != "complete":
        raise ValueError("the cycle must have completed all four stages")
    out = Path(out) if out else cycle.path / "report"
    out.mkdir(parents=True, exist_ok=True)
    res = results_json(cycle)
    (out / "results.json").write_text(json.dumps(res, indent=2, sort_keys=True) + "\n")
    x = ex.build(cycle, item_id=item_id, runs=runs)
    (out / "exhibit.json").write_text(json.dumps(x, indent=2, sort_keys=True) + "\n")
    (out / "EXHIBIT.html").write_text(_html(x, f"Three GREENs: {cycle.id}"))
    s = {n: cycle.data["stages"][str(n)]["outcome"] for n in range(1, 5)}
    with (out / "timing.csv").open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["target_records", "actual_records", "repetitions", "median_ms", "max_ms", "exceedances", "not_ready"])
        for v, r in s[3]["volumes"].items():
            w.writerow([v, " ".join(map(str, r["actual"])), r["repetitions"], r["median_ms"], r["max_ms"], r["exceedances"], r["not_ready"]])
    with (out / "assurance.csv").open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["view", "attainable", "verdict_only", "oracle", "observed", "action", "agree", "missing", "note"])
        for vid, r in s[4]["views"].items():
            w.writerow([vid, r["attainable"], r["verdict_only"], r["oracle"], r["observed"], r["action"], r["agree"],
                        " ".join(r["missing"] or []), r["note"]])
    lock = protocol_dir() / "protocol.lock.json"
    paper = paper_tex.build(lock if lock.exists() else None, out / "results.json")
    paper_tex.write(out / "paper", paper)
    md = [f"# Results: cycle {cycle.id}", "",
          f"Mode **{cycle.data['mode']}**{' (imported fixture, not a result of this study)' if cycle.data.get('imported_from') else ''}"
          f" · protocol lock `{str(cycle.data.get('protocol_lock_sha256'))[:16]}` · code `{str(cycle.data['code']['commit'])[:12]}`", "",
          "| Stage | Outcome |", "|---|---|",
          f"| 1 Acquire and freeze | {s[1]['repoaudit_runs']} RepoAudit runs ({s[1]['repoaudit_green']} GREEN, {s[1]['repoaudit_adverse']} adverse, "
          f"{s[1]['repoaudit_failed']} failed) · {s[1]['semgrep_runs']} Semgrep · evidence bed `{s[1]['sealed_manifest_sha256'][:16]}` |",
          f"| 2 ProofWeave within the threshold | median {s[2]['median_ms']} ms · max {s[2]['max_ms']} ms · "
          f"{s[2]['within_threshold']}/{s[2]['observations']} within {s[2]['threshold_s']} s · corpus E `{s[2]['corpus_sha256'][:16]}` |",
          f"| 3 Scale | up to {s[3]['largest_volume']} records · max {s[3]['max_ready_ms_at_largest']} ms · crossing: {s[3]['threshold_crossing']} |",
          f"| 4 Three GREENs | {s[4]['three_green_case']} · oracle {s[4]['oracle_agreement']} · unsupported PROCEED "
          f"{s[4]['unsupported_proceed']} · replay {s[4]['replay_agreement']} |", "",
          "Tables: `timing.csv`, `assurance.csv` · paper LaTeX: `paper/` · presentation page: `EXHIBIT.html` · "
          "graphs: `../stage2/<attempt>/corpus/graph.dot`, `../stage4/<attempt>/views/*.dot`", ""]
    md += _md_exhibit(x)
    (out / "RESULTS.md").write_text("\n".join(md) + "\n")
    (out / "report-manifest.json").write_text(json.dumps(
        {f.name: sha256_file(f) for f in sorted(out.rglob("*")) if f.is_file() and f.name != "report-manifest.json"},
        indent=2, sort_keys=True) + "\n")
    return out
