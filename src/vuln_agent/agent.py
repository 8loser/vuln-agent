# src/vuln_agent/agent.py
import json, logging, time

from vuln_agent.context import compact, trim_result
from vuln_agent.llm import client, cost, DEFAULT_MODEL
from vuln_agent.tools import TOOLS, ToolError, call_tool, schemas

log = logging.getLogger("vuln_agent")
REFUSAL = "這個問題超出漏洞情資助理的範圍：只能查詢漏洞資料與修補優先順序，不提供攻擊程式、payload 或繞過防護的方法。"

SYSTEM = """你是漏洞情資助理，用繁體中文回答，漏洞資料一律用工具查。
- 只能提到工具結果裡出現的 CVE 編號與分數，不要憑記憶補充；漏洞俗稱（例如 log4shell）要先用工具查出對應的 CVE
- 要求攻擊程式、payload、繞過防護，或跟漏洞情資無關的問題，直接拒絕，不呼叫工具
- 工具回傳錯誤時，依錯誤訊息修正參數再試；查不到就說資料庫裡查不到
- 說明順序：先講在 KEV（已被利用）的，再講 EPSS 高的"""

def run_agent(question: str, tools=TOOLS, model: str = DEFAULT_MODEL, max_steps: int = 8, timeout: float = 120,
              trim_tokens: int | None = None, context_tokens: int | None = None):
    """手寫的 tool-use loop，每發生一件事就 yield 一個 (事件, 資料)：
    text（模型的文字，逐段）、tool_use（要呼叫的工具與參數）、tool_result（工具結果）、done（停止原因與總計）。
    停止條件：模型不再要求呼叫工具、達到 max_steps、超過 timeout 秒。
    階段 3 的 context 管理（預設關閉）：trim_tokens 是單一工具結果的上限，context_tokens 是整段對話的上限。"""
    messages = [{"role": "user", "content": question}]
    tool_schemas = schemas(tools)
    usages, start, stop = [], time.time(), "max_steps"
    for step in range(1, max_steps + 1):
        if time.time() - start > timeout:
            stop = "timeout"
            break
        if context_tokens and (compacted := compact(messages, context_tokens)) is not messages:
            log.info(json.dumps({"step": step, "compacted_messages": len(messages)}, ensure_ascii=False))
            messages = compacted
        t = time.time()
        with client.messages.stream(model=model, max_tokens=2048, system=SYSTEM,
                                    tools=tool_schemas, messages=messages) as stream:
            for chunk in stream.text_stream:
                yield "text", chunk
            resp = stream.get_final_message()
        usages.append(resp.usage)
        calls = []
        if resp.stop_reason == "tool_use":
            messages.append({"role": "assistant", "content": resp.content})
            results = []
            for block in (b for b in resp.content if b.type == "tool_use"):
                yield "tool_use", {"name": block.name, "input": block.input}
                t_tool = time.time()
                try:
                    result = call_tool(tools, block.name, block.input)
                    if trim_tokens:  # 接進 messages 之前就裁好，歷史只追加、不改寫
                        result = trim_result(result, trim_tokens)
                    content, is_error = json.dumps(result, ensure_ascii=False, default=str), False
                except Exception as e:  # 錯誤也包成 tool result 回給模型，loop 不中斷
                    if not isinstance(e, ToolError):
                        log.exception("工具 %s 執行失敗", block.name)
                    content, is_error = str(e) if isinstance(e, ToolError) else f"工具執行失敗：{e!r}", True
                yield "tool_result", {"name": block.name, "content": content, "is_error": is_error}
                results.append({"type": "tool_result", "tool_use_id": block.id,
                                "content": content, "is_error": is_error})
                calls.append({"tool": block.name, "input": block.input, "is_error": is_error,
                              "seconds": round(time.time() - t_tool, 2)})
            messages.append({"role": "user", "content": results})
        log.info(json.dumps({"step": step, "tools": calls, "seconds": round(time.time() - t, 2),
                             "input_tokens": resp.usage.input_tokens, "output_tokens": resp.usage.output_tokens,
                             "cost_usd": round(cost(resp.usage, model), 6)}, ensure_ascii=False))
        if resp.stop_reason != "tool_use":
            stop = resp.stop_reason
            break
    if stop in ("max_steps", "timeout"):
        reason = f"已達最大步數 {max_steps}" if stop == "max_steps" else f"超過 {timeout} 秒"
        yield "text", f"\n\n查詢未完成：{reason}，以上是目前查到的部分。"
    elif stop == "refusal":  # 被安全分類器擋下時回答是空的，補上跟 SYSTEM 拒絕規則一致的說明（同 intent.py 的處理）
        yield "text", REFUSAL
    summary = {"stop": stop, "steps": len(usages), "seconds": round(time.time() - start, 2),
               "input_tokens": sum(u.input_tokens for u in usages),
               "output_tokens": sum(u.output_tokens for u in usages),
               "cost_usd": round(sum(cost(u, model) for u in usages), 6)}
    log.info(json.dumps({"question": question, **summary}, ensure_ascii=False))
    yield "done", summary

def ask(question: str, **kwargs) -> dict:
    """跑完整個 loop，把事件收成一個結果：回答、每次工具呼叫（含結果）與總計。"""
    answer, calls, summary = [], [], {}
    for event, data in run_agent(question, **kwargs):
        if event == "text":
            answer.append(data)
        elif event == "tool_use":
            calls.append(data)
        elif event == "tool_result":
            calls[-1].update(result=data["content"], is_error=data["is_error"])
        else:
            summary = data
    return {"answer": "".join(answer), "tool_calls": calls, **summary}
