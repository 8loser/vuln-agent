# src/vuln_agent/api.py
import json, logging, time
from fastapi import FastAPI
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from vuln_agent.llm import client, cost, DEFAULT_MODEL
from vuln_agent.intent import parse
from vuln_agent import queries

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("vuln_agent")
app = FastAPI()

ANSWER_SYSTEM = """你是漏洞情資助理，用繁體中文回答。
- 只能根據使用者訊息裡的「查詢結果」回答，只能提到查詢結果裡出現的 CVE 編號
- 查詢結果是空的，就說資料庫裡查不到符合條件的漏洞，不要憑記憶補充
- 依查詢結果的順序說明，先講在 KEV（已被利用）的，再講 EPSS 高的"""

class Question(BaseModel):
    question: str

def record(endpoint: str, timings: dict, usages: list):
    """每個請求寫一行 JSON log：各段耗時、tokens、花費。"""
    log.info(json.dumps({
        "endpoint": endpoint,
        "seconds": {k: round(v, 2) for k, v in timings.items()},
        "input_tokens": sum(u.input_tokens for u in usages),
        "output_tokens": sum(u.output_tokens for u in usages),
        "cost_usd": round(sum(cost(u) for u in usages), 6),
    }))

def parse_and_query(q: Question, timings: dict, usages: list):
    t = time.time()
    intent = parse(q.question, usages=usages)
    timings["parse"] = time.time() - t
    t = time.time()
    rows = queries.run(intent)
    timings["sql"] = time.time() - t
    return intent, rows

@app.post("/parse")
def parse_endpoint(q: Question):
    timings, usages = {}, []
    t = time.time()
    intent = parse(q.question, usages=usages)
    timings["parse"] = time.time() - t
    record("/parse", timings, usages)
    return intent

@app.post("/ask")
def ask_endpoint(q: Question):
    timings, usages = {}, []
    intent, rows = parse_and_query(q, timings, usages)
    record("/ask", timings, usages)
    return {"intent": intent, "rows": rows}

@app.post("/ask/stream")
def ask_stream(q: Question):
    """SSE 串流：先送 intent 與查詢結果，再逐段送模型的中文說明，最後送 done。"""
    def events():
        timings, usages = {}, []
        intent, rows = parse_and_query(q, timings, usages)
        yield sse("intent", intent.model_dump())
        yield sse("rows", rows)
        if intent.intent == "unsupported":
            yield sse("text", f"這個問題不在服務範圍內：{intent.reason or '只回答漏洞情資查詢'}")
        else:
            t = time.time()
            content = f"問題：{q.question}\n\n查詢結果（JSON）：\n{json.dumps(rows, ensure_ascii=False, default=str)}"
            with client.messages.stream(model=DEFAULT_MODEL, max_tokens=2048, system=ANSWER_SYSTEM,
                                        messages=[{"role": "user", "content": content}]) as stream:
                for chunk in stream.text_stream:
                    yield sse("text", chunk)
                usages.append(stream.get_final_message().usage)
            timings["answer"] = time.time() - t
        record("/ask/stream", timings, usages)
        yield sse("done", {})
    return StreamingResponse(events(), media_type="text/event-stream")

def sse(event: str, data) -> str:
    return f"event: {event}\ndata: {json.dumps(data, ensure_ascii=False, default=str)}\n\n"
