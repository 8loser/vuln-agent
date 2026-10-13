# src/vuln_agent/llm.py
import os
from anthropic import Anthropic
from dotenv import load_dotenv

load_dotenv()
# 自動讀 ANTHROPIC_API_KEY；SDK 遇到 429、5xx、連線錯誤會自動退避重試，這裡設成最多 3 次，單次逾時 60 秒
client = Anthropic(timeout=60, max_retries=3)
DEFAULT_MODEL = os.getenv("MODEL", "claude-sonnet-5-5")

def ask(messages, model=DEFAULT_MODEL, max_tokens=1024, **kwargs):
    """送一次 Messages API 請求，回傳完整的回應物件。其他參數（system、thinking 等）用 kwargs 傳。"""
    return client.messages.create(model=model, max_tokens=max_tokens, messages=messages, **kwargs)

def text(resp):
    """把回應裡的文字 block 串成一個字串；thinking 等其他 block 略過。"""
    return "".join(b.text for b in resp.content if b.type == "text")

# 每百萬 token 的美元價格：輸入、輸出、快取讀取（2026-10 官方定價）
# 快取寫入以 5 分鐘 TTL 計，為輸入價的 1.25 倍
PRICES = {
    "claude-opus-5-5": (4.00, 20.00, 0.20),
    "claude-sonnet-5-5": (2.00, 10.00, 0.20),
    "claude-haiku-5-5": (0.10, 0.50, 0.01),  # 提示 100K token 以內的價格，超過改為 0.50 / 2.50
}

def cost(usage, model=DEFAULT_MODEL):
    """依 PRICES 把回應的 usage 換算成美元，含輸入、輸出、快取讀取與快取寫入。"""
    inp, out, cache_read = PRICES[model]
    total = (usage.input_tokens * inp
             + usage.output_tokens * out
             + (usage.cache_read_input_tokens or 0) * cache_read
             + (usage.cache_creation_input_tokens or 0) * inp * 1.25)
    return total / 1_000_000
