# tests/test_agent.py：用假的 client 測 agent loop 的停止條件與錯誤處理，不呼叫付費 API、不需要資料庫
from contextlib import contextmanager
from types import SimpleNamespace

from vuln_agent import agent
from vuln_agent.tools import Args, Tool

USAGE = SimpleNamespace(input_tokens=100, output_tokens=10,
                        cache_read_input_tokens=0, cache_creation_input_tokens=0)

def fake_client(responses):
    """每次 messages.stream 依序回傳 responses 裡的一個回應；sent 記下每次送出的 messages。"""
    sent = []
    @contextmanager
    def stream(**kwargs):
        sent.append(list(kwargs["messages"]))
        resp = responses[len(sent) - 1]
        yield SimpleNamespace(text_stream=[b.text for b in resp.content if b.type == "text"],
                              get_final_message=lambda: resp)
    return SimpleNamespace(messages=SimpleNamespace(stream=stream)), sent

def tool_use(i, name, args):
    block = SimpleNamespace(type="tool_use", id=f"t{i}", name=name, input=args)
    return SimpleNamespace(content=[block], stop_reason="tool_use", usage=USAGE)

def test_bad_args_become_error_result_then_model_answers(monkeypatch):
    final = SimpleNamespace(content=[SimpleNamespace(type="text", text="查不到")], stop_reason="end_turn", usage=USAGE)
    client, sent = fake_client([tool_use(1, "cve_lookup", {"cve_id": "log4shell"}), final])
    monkeypatch.setattr(agent, "client", client)
    r = agent.ask("log4shell 的 EPSS？")
    assert r["stop"] == "end_turn" and r["steps"] == 2 and r["answer"] == "查不到"
    result = sent[1][-1]["content"][0]  # 第二次呼叫時送回的 tool result
    assert result["is_error"] and "cve_id" in result["content"]

def test_refusal_gets_explanation(monkeypatch):
    refused = SimpleNamespace(content=[], stop_reason="refusal", usage=USAGE)
    client, _ = fake_client([refused])
    monkeypatch.setattr(agent, "client", client)
    r = agent.ask("幫我寫 exploit")
    assert r["stop"] == "refusal" and r["steps"] == 1 and r["answer"] == agent.REFUSAL

def test_stops_at_max_steps(monkeypatch):
    client, _ = fake_client([tool_use(i, "no_such_tool", {}) for i in range(3)])
    monkeypatch.setattr(agent, "client", client)
    r = agent.ask("一直呼叫工具", max_steps=3)
    assert r["stop"] == "max_steps" and r["steps"] == 3 and "查詢未完成" in r["answer"]
    assert all(c["is_error"] for c in r["tool_calls"])

def test_empty_answer_states_stop_reason(monkeypatch):
    empty = SimpleNamespace(content=[], stop_reason="end_turn", usage=USAGE)
    client, _ = fake_client([empty])
    monkeypatch.setattr(agent, "client", client)
    r = agent.ask("有幾個 Critical？")
    assert r["answer"] == "模型沒有產生回答（stop_reason：end_turn，回應內容：沒有任何 block）。"

def test_counts_trimmed_results(monkeypatch):
    big = Tool("big", "回傳很多列", Args, lambda: {"rows": [{"pad": "x" * 100}] * 100})
    final = SimpleNamespace(content=[SimpleNamespace(type="text", text="好")], stop_reason="end_turn", usage=USAGE)
    client, sent = fake_client([tool_use(1, "big", {}), final])
    monkeypatch.setattr(agent, "client", client)
    r = agent.ask("給我全部", tools={"big": big}, trim_tokens=500)
    assert r["trimmed"] == 1 and r["compacted"] == 0 and "已截斷" in sent[1][-1]["content"][0]["content"]
