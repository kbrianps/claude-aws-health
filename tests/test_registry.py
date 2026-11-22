from awshealth.collect.engine import gather
from awshealth.registry import load_checks, required_calls


def test_every_per_item_parent_is_declared_by_the_same_check():
    for cid, spec in load_checks().items():
        ops = {(c.service, c.operation) for c in spec.requires}
        for c in spec.requires:
            if c.per_item:
                assert (c.per_item[0], c.per_item[1]) in ops, f"{cid}: {c.key} needs its parent in requires"


def test_registered_checks_gather_without_conflicts():
    specs = load_checks()
    assert required_calls(specs)
    run, skipped, parents = gather(specs, metrics=False, cost=False)
    assert run and all(p.key in {c.key for c in run + skipped} for p in parents.values())


def test_every_check_has_bilingual_title_and_known_catalog_ids():
    import json
    from pathlib import Path

    import awshealth

    catalog = {c["id"] for c in json.loads((Path(awshealth.__file__).parent / "data" / "catalog.json").read_text())}
    for cid, spec in load_checks().items():
        assert spec.title["en"] and spec.title["pt-BR"], cid
        assert set(spec.catalog_ids) <= catalog, (cid, set(spec.catalog_ids) - catalog)
