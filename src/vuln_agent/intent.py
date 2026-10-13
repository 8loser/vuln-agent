# src/vuln_agent/intent.py
import re
from typing import Literal
from anthropic import transform_schema
from pydantic import BaseModel, Field, ValidationError, field_validator

from vuln_agent.llm import client, text, DEFAULT_MODEL

class QueryIntent(BaseModel):
    """使用者問題解析出的查詢條件；步驟 4 依 intent 選 SQL 樣板，其他欄位當參數。"""
    intent: Literal["cve_lookup", "search", "count", "unsupported"]
    cve_id: str | None = Field(None, description="問題裡明確寫出的 CVE 編號")
    product: str | None = Field(None, description="產品名稱，小寫，例如 nginx")
    cwe: str | None = Field(None, description="弱點類型，例如 SQL injection 是 CWE-89")
    min_cvss: float | None = Field(None, description="CVSS 下限，0 到 10；「高風險」對應 7")
    in_kev: bool | None = Field(None, description="問「已經被利用」時為 true")
    min_epss: float | None = Field(None, description="EPSS 下限，0 到 1")
    days: int | None = Field(None, description="只看最近幾天發布的漏洞，「最近 30 天」是 30")
    reason: str | None = Field(None, description="intent 是 unsupported 時，簡短說明原因")

    @field_validator("cve_id")
    @classmethod
    def check_cve(cls, v):
        if v is not None and not re.fullmatch(r"CVE-\d{4}-\d{4,}", v):
            raise ValueError(f"cve_id 格式應為 CVE-年份-流水號，收到 {v!r}")
        return v

    @field_validator("cwe")
    @classmethod
    def check_cwe(cls, v):
        if v is not None and not re.fullmatch(r"CWE-\d+", v):
            raise ValueError(f"cwe 格式應為 CWE-數字，收到 {v!r}")
        return v

SYSTEM = """你把使用者的漏洞問題解析成查詢條件。
- 只解析，不回答問題，也不要憑記憶補任何 CVE 編號
- 要求攻擊程式、payload、繞過防護，或跟漏洞情資無關的問題，intent 一律是 unsupported"""

# 用 SDK 的 transform_schema 把 QueryIntent 轉成 API 接受的 JSON Schema（加上 additionalProperties: false 等）
FORMAT = {"type": "json_schema", "schema": transform_schema(QueryIntent)}

def parse(question: str, model: str = DEFAULT_MODEL, usages: list | None = None) -> QueryIntent:
    """用 structured outputs 把問題解析成 QueryIntent；Pydantic 驗證失敗時，把錯誤丟回模型重試一次。
    有傳 usages 的話，每次呼叫的 usage 都會加進去，給呼叫端算 tokens 與花費。"""
    messages = [{"role": "user", "content": question}]
    for attempt in range(2):
        resp = client.messages.create(model=model, max_tokens=2048, system=SYSTEM,
                                      messages=messages, output_config={"format": FORMAT})
        if usages is not None:
            usages.append(resp.usage)
        if resp.stop_reason == "refusal":  # 模型拒答時回答是空的，改走跟 SYSTEM 規則一樣的 unsupported
            return QueryIntent(intent="unsupported", reason="模型拒絕回答這個問題")
        try:
            return QueryIntent.model_validate_json(text(resp))
        except ValidationError as e:
            if attempt == 1:
                raise
            messages += [{"role": "assistant", "content": resp.content},
                         {"role": "user", "content": f"上面的輸出沒有通過驗證，請修正後重新輸出：\n{e}"}]
