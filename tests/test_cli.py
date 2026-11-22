import json
import re
import shutil
import subprocess
import sys

import pytest

from awshealth.cli import main
from awshealth.demo import demo_dir


@pytest.fixture
def old_run(tmp_path, monkeypatch):
    monkeypatch.setenv("AWSHEALTH_HOME", str(tmp_path / "home"))
    run = tmp_path / "run"
    run.mkdir()
    shutil.copyfile(demo_dir() / "snapshot.json", run / "snapshot.json")
    return run


def test_check_uses_the_snapshot_time_and_prints_a_summary(old_run, capsys):
    main(["check", "--run", str(old_run)])
    out = capsys.readouterr().out
    assert out.splitlines()[0].startswith("34 checks: ")
    assert "findings: " in out and f"run: {old_run}" in out and "{" not in out
    eks = [f for f in json.loads((old_run / "findings.json").read_text()) if f["check_id"] == "eks-extended-support"]
    assert eks and all("in 16 days" in f["text"]["en"]["title"] for f in eks)


def test_render_uses_the_snapshot_time(old_run, capsys):
    main(["check", "--run", str(old_run)])
    main(["render", "--run", str(old_run)])
    assert "2026-02-01 (in 16 days)" in (old_run / "report.md").read_text()


def test_demo_defaults_to_a_folder_in_the_current_directory(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("AWSHEALTH_HOME", str(tmp_path / "home"))
    monkeypatch.chdir(tmp_path)
    main(["demo"])
    assert (tmp_path / "awshealth-demo" / "report.html").exists()
    assert not (tmp_path / "home").exists()


def test_verify_unknown_uid_exits_with_a_message(old_run, capsys):
    main(["check", "--run", str(old_run)])
    capsys.readouterr()
    with pytest.raises(SystemExit) as exc:
        main(["verify", "--run", str(old_run), "nope:000000000000"])
    assert "no finding" in str(exc.value.code) and "nope:000000000000" in str(exc.value.code)
    main(["verify", "--run", str(old_run), "eks-extended-support"])
    assert "aws eks " in capsys.readouterr().out


def test_catalog_rejects_an_unknown_category():
    with pytest.raises(SystemExit) as exc:
        main(["catalog", "--category", "xyz"])
    assert "valid categories: cost, errors" in str(exc.value.code)


@pytest.mark.parametrize("cmd", ["check", "import", "render", "verify"])
def test_every_run_option_has_help(cmd, capsys):
    with pytest.raises(SystemExit):
        main([cmd, "--help"])
    assert re.search(r"--run RUN\s+run directory; default: the latest run", capsys.readouterr().out)


def test_catalog_into_a_closed_pipe_has_no_traceback():
    p = subprocess.Popen([sys.executable, "-m", "awshealth.cli", "catalog", "--format", "json"],
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    p.stdout.read(10)
    p.stdout.close()
    err = p.stderr.read().decode()
    p.wait(timeout=30)
    assert "Traceback" not in err and "BrokenPipeError" not in err
