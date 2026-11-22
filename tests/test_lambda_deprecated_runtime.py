from awshealth.calls_compute import FUNCTIONS
from awshealth.testing import run_one, snap_with


def fn(name, runtime):
    return {"name": name, "arn": f"arn:aws:lambda:us-east-1:111122223333:function:{name}", "runtime": runtime,
            "modified": "2024-05-01T00:00:00.000+0000"}


def snap(*functions):
    return snap_with({FUNCTIONS: {"us-east-1": list(functions)}})


def by_runtime(findings):
    return {f.resource.rsplit("/", 1)[1]: f for f in findings}


def test_deprecated_runtime_groups_functions_with_next_deadline():
    found = by_runtime(run_one("lambda-deprecated-runtime", snap(fn("a", "python3.8"), fn("b", "python3.8"))))
    f = found["python3.8"]
    assert f.severity == "medium"
    assert len(f.resources) == 2
    assert f.deadline.startswith("2027-07-29")
    assert "python3.8" in f.verify[0] and "--region us-east-1" in f.verify[0]


def test_blocked_update_is_high_and_soon_deprecated_is_low():
    found = by_runtime(run_one("lambda-deprecated-runtime", snap(fn("old", "nodejs12.x"), fn("rb", "ruby3.2"))))
    assert found["nodejs12.x"].severity == "high"
    assert found["nodejs12.x"].deadline == ""
    assert found["ruby3.2"].severity == "low"
    assert "74 days" in found["ruby3.2"].t("title")
    assert found["ruby3.2"].deadline.startswith("2026-03-31")


def test_supported_image_and_custom_runtimes_are_quiet():
    assert run_one("lambda-deprecated-runtime", snap(fn("new", "python3.12"), fn("img", None),
                                                    fn("custom", "provided.al2023"))) == []
