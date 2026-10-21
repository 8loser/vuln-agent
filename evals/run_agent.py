# evals/run_agent.py：用 seed.jsonl 跑 agent，做三項程式斷言，輸出摘要表（含錯誤呼叫數），逐題結果存成 jsonl
# 用法：uv run evals/run_agent.py [--toolsets A B C D E] [--runs 1] [--model claude-sonnet-5-5]
# 會呼叫付費 API：20 題 × 工具組數 × 次數
import argparse, json, re, sys
from datetime import datetime
from pathlib import Path

from vuln_agent.agent import ask
from vuln_agent.llm import DEFAULT_MODEL
from toolsets import TOOLSETS, tool_names

HERE = Path(__file__).parent
CASES = [json.loads(line) for line in (HERE / "seed.jsonl").read_text().splitlines()]
CVE = re.compile(r"CVE-\d{4}-\d{4,}")
MAX_STEPS = 8

def check(case: dict, r: dict) -> dict:
    """三項斷言：
    tools：呼叫的工具都在 expected_tools 裡，該拒絕的題目一個都不呼叫、其他題目至少呼叫一個
    steps：模型自己結束，沒有撞到最大步數或逾時
    cves：回答裡的 CVE 都出現在工具結果或問題裡（沒有憑記憶編造）"""
    called, expected = tool_names(r["tool_calls"]), set(case["expected_tools"])
    seen = set(CVE.findall(case["question"] + "".join(c.get("result", "") for c in r["tool_calls"])))
    return {"tools": called <= expected and bool(called) == bool(expected),
            "steps": r["stop"] not in ("max_steps", "timeout"),
            "cves": set(CVE.findall(r["answer"])) <= seen}

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--toolsets", nargs="+", default=["C"], choices=TOOLSETS)
    p.add_argument("--runs", type=int, default=1)
    p.add_argument("--model", default=DEFAULT_MODEL)
    a = p.parse_args()

    out = HERE / "results" / f"{datetime.now():%Y%m%d-%H%M}-{a.model}.jsonl"
    out.parent.mkdir(exist_ok=True)
    print(f"{'工具組':6} {'選擇正確':>8} {'三項全過':>8} {'錯誤呼叫':>8} {'平均步數':>8} {'平均 tokens':>11} {'總花費 USD':>10}")
    failed = False
    with out.open("w") as f:
        for name in a.toolsets:
            results = []
            for run in range(a.runs):
                for case in CASES:
                    r = ask(case["question"], tools=TOOLSETS[name], model=a.model, max_steps=MAX_STEPS)
                    ok = check(case, r)
                    results.append((r, ok))
                    f.write(json.dumps({"toolset": name, "run": run, "question": case["question"],
                                        "expected_tools": case["expected_tools"], "check": ok, **r},
                                       ensure_ascii=False, default=str) + "\n")
                    if not all(ok.values()):
                        print(f"  [{name}] 沒過 {[k for k, v in ok.items() if not v]}：{case['question']}"
                              f" -> {sorted(tool_names(r['tool_calls']))}")
            n = len(results)
            passed = sum(all(ok.values()) for _, ok in results)
            failed |= passed < n
            # 錯誤呼叫只計數、不算沒過：模型收到錯誤訊息後修正參數是合理行為，但每次都多花一步
            errors = sum(c.get("is_error", False) for r, _ in results for c in r["tool_calls"])
            print(f"{name:6} {sum(ok['tools'] for _, ok in results):>4}/{n:<3} {passed:>4}/{n:<3} {errors:>8}"
                  f" {sum(r['steps'] for r, _ in results) / n:>8.1f}"
                  f" {sum(r['input_tokens'] + r['output_tokens'] for r, _ in results) / n:>11.0f}"
                  f" {sum(r['cost_usd'] for r, _ in results):>10.4f}")
    print(f"逐題結果：{out}")
    sys.exit(1 if failed else 0)
