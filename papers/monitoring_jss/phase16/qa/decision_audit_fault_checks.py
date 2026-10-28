"""New invented-observation checks of the independent sealed-decision audit."""
import copy
import json
from pathlib import Path
import tempfile
import audit_decisions as review


def invented_observations(day, n):
    import sys
    sys.path.insert(0, str(review.PAPER / "phase15" / "adapter"))
    from retained_observation_core import observe
    start = review.driver.frozen.day_start(day)
    address = "0x" + "a" * 40; token = "0x" + "b" * 40; outside = "0x" + "c" * 40
    topic = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
    result = []
    for index in range(n):
        tx = {"chain_id": 1, "block_number": 1000 + index, "block_hash": "0x" + format(1000 + index, "064x"),
              "transaction_hash": "0x" + format(10000 + index, "064x"), "transaction_index": 0,
              "event_time_ns": start + index * 300_000_000_000}
        amount = index + 1 if index < 132 else 132 if index < 140 else 0
        logs = [{k: v for k, v in tx.items() if k != "chain_id"} |
                {"address": address, "topics": [], "data": "0x", "log_index": i} for i in range(10)]
        logs.append({k: v for k, v in tx.items() if k != "chain_id"} | {"address": token,
            "topics": [topic, "0x" + "0" * 24 + address[2:], "0x" + "0" * 24 + outside[2:]],
            "data": "0x" + format(amount, "064x"), "log_index": 10})
        result.append(observe(tx, logs, [address], 10, "a" * 64, "b" * 64, dataset_execution_status=1))
    return result


def materialize(config, day, observations, folder):
    # Existing frozen production function is used only on this new invented
    # fixture; no previous suite, historical row, label or accepted replay runs.
    frozen = review.driver.frozen
    output = frozen.replay_day(config, day, observations, source_audit_sha256="a" * 64,
                               source_scope=config["source_scope"])
    folder.mkdir()
    for method, rows in output["methods"].items():
        frozen.write_jsonl_gzip(folder / (method + "__methods.jsonl.gz"), rows)
    for key, rows in output["decisions"].items():
        frozen.write_jsonl_gzip(folder / ("__".join(map(str, key)) + "__decisions.jsonl.gz"), rows)
    for key in ("method_summaries", "cell_summaries", "final_method_states", "final_policy_states"):
        frozen.write_json(folder / (key + ".json"), output[key])
    return output


def run():
    config = review.read(review.PAPER / "phase16" / "protocol" / "configs" / "lifi.json")
    config = copy.deepcopy(config); config["population_addresses"] = ["0x" + "a" * 40]
    checks = []
    with tempfile.TemporaryDirectory(prefix="phase16_decision_audit_fixture_") as directory:
        root = Path(directory); day = "2022-02-19"
        obs = invented_observations(day, 145)
        generated = materialize(config, day, obs, root / "first")
        summaries = review.audit_day(config, day, obs, root / "first", "a" * 64)
        assert len(summaries) == 27
        checks.append("all27_cells_and_final_states_match_frozen_engine_on145_invented_observations")
        semantic, state = review.calculate_methods(obs, review.METHODS[1], review.driver.frozen.day_start(day))
        assert semantic[18]["eligible_token_count"] == 0
        assert semantic[19]["token_scores"][0]["tail_rank"] == {"numerator": 1, "denominator": 20}
        assert semantic[19]["raw_trigger"] is True
        assert semantic[131]["token_scores"][0]["history_count"] == 128
        assert semantic[132]["token_scores"][0]["tail_rank"]["numerator"] == 2
        assert semantic[144]["positive_token_count"] == 0
        checks.append("strict_past19_warmup128_truncation_ties_and_zero_outflows_checked")
        chosen = root / "first" / "outflow_rank_1_20__methods.jsonl.gz"
        corrupt = list(review.rows(chosen)); corrupt[19]["token_scores"][0]["tail_rank"]["numerator"] = 2
        chosen.unlink()
        review.driver.frozen.write_jsonl_gzip(chosen, corrupt)
        try:
            review.audit_day(config, day, obs, root / "first", "a" * 64)
        except ValueError as exc:
            assert "independent method equation" in str(exc)
        else:
            raise AssertionError("tampered rank accepted")
        checks.append("tampered_sealed_rank_rejected_by_independent_calculation")
        next_day = "2022-02-20"; next_obs = invented_observations(next_day, 1)
        materialize(config, next_day, next_obs, root / "second")
        review.audit_day(config, next_day, next_obs, root / "second", "a" * 64)
        first, _ = review.calculate_methods(next_obs, review.METHODS[1], review.driver.frozen.day_start(next_day))
        assert first[0]["token_scores"][0]["history_count"] == 0 and first[0]["group_candidate"] is False
        checks.append("next_utc_day_has_zero_semantic_history_and_fresh_admission_state")
        materialize(config, "2022-02-21", [], root / "empty")
        review.audit_day(config, "2022-02-21", [], root / "empty", "a" * 64)
        checks.append("covered_empty_day_preserves27_zero_load_cells_and_empty_final_states")
        near = copy.deepcopy(obs[:3]); start = review.driver.frozen.day_start(day)
        for row, delta in zip(near, [0, 59, 60]):
            row["transaction"]["event_time_ns"] = start + delta * 10**9
            row["archived_core_log_count"] = 1
        counts, _ = review.calculate_methods(near, review.METHODS[0], start)
        assert [x["rolling_core_log_count"] for x in counts] == [1, 2, 2]
        checks.append("count_window_excludes_exact60second_left_boundary")
        candidates = [{"transaction": x["transaction"], "group_candidate": True} for x in obs[:2]]
        for policy, reason in (("greedy", "emitted"), ("paced_cumulative", "paced_quota"), ("token_bucket", "token_shortage")):
            admissions, _ = review.policy_reference(candidates, policy, 5, review.METHODS[0], start)
            assert admissions[0]["notification_emitted"] is True and admissions[1]["suppression_reason"] == reason
        checks.append("independent_integer_budget_equations_distinguish_all3_policies")
    return {"status": "PASS_NEW_SYNTHETIC_DECISION_AUDITOR_CHECKS_ONLY", "checks_passed": len(checks), "checks": checks,
            "reviewer_sha256": review.file_sha(review.__file__), "test_script_sha256": review.file_sha(__file__),
            "real_source_rows": 0, "actual_replay_runs": 0, "labels_used": False, "old_suites_rerun": False}


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description=__doc__); p.add_argument("--report", type=Path, required=True)
    args = p.parse_args(); result = run(); args.report.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"status": result["status"], "checks_passed": result["checks_passed"]}))
