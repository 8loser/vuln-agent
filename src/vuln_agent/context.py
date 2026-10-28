# src/vuln_agent/context.py：階段 3 的 context 管理。trim_result 管單一工具結果，compact 管整段對話
import json

# 用字元數粗估 token，不連網、不花錢。2026-10 用 count_tokens 對 claude-sonnet-5-5 實測：
# query_findings 的 JSON 約 1.8 字元 / token、Trivy 原始 JSON 約 2.2、中文文件約 1.3。
# 工具結果大多是 JSON，取 1.8，估得偏多比較安全；比例隨模型的 tokenizer 改變（notebook 03 的 1.2），換模型要重量
CHARS_PER_TOKEN = 1.8

def to_json(obj) -> str:
    """messages 裡混著 dict 與 SDK 的 content block 物件，block 先轉成 dict 再序列化。"""
    return json.dumps(obj, ensure_ascii=False,
                      default=lambda o: o.model_dump() if hasattr(o, "model_dump") else str(o))

def estimate_tokens(obj) -> int:
    return int(len(obj if isinstance(obj, str) else to_json(obj)) / CHARS_PER_TOKEN)

def trim_result(result: dict, max_tokens: int) -> dict:
    """工具結果超過 max_tokens 時，從最長的清單尾端截掉，並寫明截了多少，模型才知道要縮小範圍；
    沒有清單、或清單第一筆就放不下時，退回直接截斷 JSON 字串。"""
    if estimate_tokens(result) <= max_tokens:
        return result
    budget = int(max_tokens * CHARS_PER_TOKEN)
    lists = [k for k, v in result.items() if isinstance(v, list)]
    if lists:
        key = max(lists, key=lambda k: len(to_json(result[k])))
        rows, out = result[key], {k: v for k, v in result.items() if k != key}
        note = lambda n: f"已截斷：{key} 只回傳 {n} / {len(rows)} 筆，請用篩選條件或分頁縮小範圍"
        # 先扣掉 note 與清單本身的長度（用最多位數的筆數估），裁完的結果才不會超過 max_tokens
        kept, used = [], len(to_json({**out, key: [], "note": note(len(rows))}))
        for row in rows:
            used += len(to_json(row)) + 2  # 清單元素之間的 ", "
            if used > budget:
                break
            kept.append(row)
        if kept:
            return {**out, key: kept, "note": note(len(kept))}
    note = f"已截斷：結果約 {estimate_tokens(result)} tokens，只保留開頭，請用篩選條件縮小範圍"
    text, room = to_json(result), budget - len(to_json({"partial_json": "", "note": note}))
    cut = room
    while len(to_json(text[:cut])) - 2 > room:  # 字串再序列化時引號會跳脫成 \"，要用跳脫後的長度比
        cut -= len(to_json(text[:cut])) - 2 - room
    return {"partial_json": text[:cut], "note": note}

def compact(messages: list, max_tokens: int) -> list:
    """simple compaction：估算超過 max_tokens 時，把整段對話換成一則 user 訊息，從這則摘要重新開始。
    摘要包含原始問題、模型已經說過的結論、每次工具呼叫的一行紀錄，以及最近一次的工具結果。
    舊訊息整段換掉、不回放，所以不會改寫到被 thinking block 綁定的歷史（原因見 notebook 03 的 2.2）。
    呼叫時機是每輪呼叫模型前，這時最後一則是使用者問題或工具結果，不會切在 tool_use 等結果的中間。"""
    if estimate_tokens(messages) <= max_tokens:
        return messages
    question = messages[0]["content"]
    conclusions, calls, last_results = [], {}, []
    for m in messages[1:]:
        blocks = m["content"] if isinstance(m["content"], list) else []
        if m["role"] == "assistant":
            for b in blocks:
                if b.type == "text" and b.text.strip():
                    conclusions.append(b.text.strip())
                elif b.type == "tool_use":
                    calls[b.id] = f"{b.name}({to_json(b.input)})"
        elif results := [b for b in blocks if b["type"] == "tool_result"]:
            last_results = results
            for b in results:
                calls[b["tool_use_id"]] += f" → {b['content'][:150]}…（共 {len(b['content'])} 字元）"
    # ponytail: 再次壓縮時，上一次的摘要會成為新的「原始問題」整段保留；對話極長時摘要會累積變大，需要時改成只保留最初的問題
    summary = "\n".join([
        question, "",
        "[前面的對話已壓縮，以下是到目前為止的進度]",
        "已說過的結論：", *(f"- {c}" for c in conclusions or ["（還沒有）"]),
        "工具呼叫紀錄：", *(f"- {c}" for c in calls.values()),
        "最近一次工具結果：", *(b["content"] for b in last_results),
        "", "請根據以上內容繼續回答原始問題；資料不夠就再呼叫工具。",
    ])
    return [{"role": "user", "content": summary}]
