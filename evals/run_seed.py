# evals/run_seed.py：用 seed.jsonl 裡有 expected 的題目比較大小兩個模型的解析命中數、平均延遲、總花費
import json, time
from pathlib import Path

from vuln_agent.intent import parse
from vuln_agent.llm import cost

MODELS = ("claude-sonnet-5-5", "claude-haiku-5-5")
# 沒有 expected 的題目（排序、統計）不在 QueryIntent 的範圍，只用在階段 2 的 agent 評測
CASES = [c for line in (Path(__file__).parent / "seed.jsonl").read_text().splitlines()
         if "expected" in (c := json.loads(line))]

def hit(intent, expected: dict) -> bool:
    """只比對 expected 有列出的欄位；product 不分大小寫。"""
    for k, v in expected.items():
        got = getattr(intent, k)
        if k == "product" and got:
            got = got.lower()
        if got != v:
            return False
    return True

if __name__ == "__main__":
    print(f"{'模型':20} {'命中':>6} {'平均秒數':>8} {'總花費 USD':>12}")
    for model in MODELS:
        hits, seconds, usd = 0, [], 0.0
        for case in CASES:
            usages = []
            t = time.time()
            try:
                intent = parse(case["question"], model=model, usages=usages)
                ok = hit(intent, case["expected"])
            except Exception as e:  # 重試後仍驗證失敗也算沒命中
                intent, ok = e, False
            seconds.append(time.time() - t)
            usd += sum(cost(u, model) for u in usages)
            hits += ok
            if not ok:
                print(f"  [{model}] 沒命中：{case['question']} -> {intent}")
        print(f"{model:20} {hits:>3}/{len(CASES)} {sum(seconds) / len(seconds):>8.1f} {usd:>12.6f}")
