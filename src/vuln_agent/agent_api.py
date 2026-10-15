# src/vuln_agent/agent_api.py：階段 2 的 API，/ask 改走 agent loop；階段 1 的版本留在 api.py
import json, logging
from fastapi import FastAPI
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from vuln_agent.agent import ask, run_agent

logging.basicConfig(level=logging.INFO)
app = FastAPI()

class Question(BaseModel):
    question: str

@app.post("/ask")
def ask_endpoint(q: Question):
    """跑完 agent loop 才回傳：回答、每次工具呼叫的參數與結果、步數、tokens、花費。"""
    return ask(q.question)

@app.post("/ask/stream")
def ask_stream(q: Question):
    """SSE 串流 agent 的每個事件：text、tool_use、tool_result，最後是 done。"""
    events = (f"event: {e}\ndata: {json.dumps(d, ensure_ascii=False, default=str)}\n\n"
              for e, d in run_agent(q.question))
    return StreamingResponse(events, media_type="text/event-stream")
