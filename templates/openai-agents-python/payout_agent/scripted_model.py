"""A stand-in for a model, so the agent runs with no account and no key. It calls approve_payout
once with the amount in the prompt, then says what the tool answered."""

import json
import re
from typing import Any

from agents import Model, ModelResponse, Usage
from openai.types.responses import ResponseFunctionToolCall, ResponseOutputMessage, ResponseOutputText


def _text(item: Any) -> str:
    content = item.get("content") if isinstance(item, dict) else None
    if isinstance(content, str):
        return content
    return " ".join(p.get("text", "") for p in content or [] if isinstance(p, dict))


class ScriptedModel(Model):
    async def get_response(self, system_instructions, input, model_settings, tools, output_schema, handoffs, tracing, **kwargs) -> ModelResponse:
        items = [{"role": "user", "content": input}] if isinstance(input, str) else list(input)
        last = items[-1]
        if isinstance(last, dict) and last.get("type") == "function_call_output":
            out = last.get("output")
            text = out if isinstance(out, str) else json.dumps(out)
            message = ResponseOutputMessage(id="msg-1", type="message", role="assistant", status="completed",
                                            content=[ResponseOutputText(type="output_text", text=text, annotations=[])])
            return ModelResponse(output=[message], usage=Usage(), response_id=None)
        words = " ".join(_text(i) for i in items if isinstance(i, dict) and i.get("role") == "user")
        m = re.search(r"(\d[\d,]*(?:\.\d+)?)", words)
        amount = float(m.group(1).replace(",", "")) if m else 0.0
        call = ResponseFunctionToolCall(type="function_call", call_id=f"call-{amount:g}", name="approve_payout",
                                        arguments=json.dumps({"payee": "Ashgrove Catering Ltd", "amount": amount, "currency": "GBP"}))
        return ModelResponse(output=[call], usage=Usage(), response_id=None)

    def stream_response(self, *args, **kwargs):
        raise NotImplementedError("the scripted model answers with get_response only")
