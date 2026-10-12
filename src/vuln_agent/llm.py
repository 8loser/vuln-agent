# src/vuln_agent/llm.py
import os
from anthropic import Anthropic
from dotenv import load_dotenv

load_dotenv()
client = Anthropic()  # 自動讀 ANTHROPIC_API_KEY
DEFAULT_MODEL = os.getenv("MODEL", "claude-sonnet-5-5")

def ask(messages, model=DEFAULT_MODEL, max_tokens=1024, **kwargs):
    return client.messages.create(model=model, max_tokens=max_tokens, messages=messages, **kwargs)

def text(resp):
    # 回應可能有 thinking 等其他 block，只取文字
    return "".join(b.text for b in resp.content if b.type == "text")

def cost(usage, model=DEFAULT_MODEL):
    # TODO：依官方定價，把 usage.input_tokens / output_tokens 換算成美元
    ...
