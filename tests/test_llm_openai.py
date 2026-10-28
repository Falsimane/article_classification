"""Transport « openai » du client LLM (SGLang, vLLM) : conversion de l'historique d'agent, appel contraint, appel d'outil (faux serveur)."""

import json
import unittest
from unittest import mock

from backend.extracting import llm


class FakeResponse:
    def __init__(self, data, status=200):
        self._data, self.status_code, self.text = data, status, json.dumps(data, ensure_ascii=False)

    def json(self):
        return self._data


class FakeSession:
    def __init__(self, data, status=200):
        self.data, self.status, self.sent = data, status, []

    def post(self, url, json=None, timeout=None):
        self.sent.append((url, json))
        return FakeResponse(self.data, self.status)


def reply(content="", tool_calls=None, finish="stop", usage=None):
    message = {"role": "assistant", "content": content}
    if tool_calls:
        message["tool_calls"] = tool_calls
    return {"choices": [{"message": message, "finish_reason": finish}], "usage": usage or {"prompt_tokens": 120, "completion_tokens": 9}}


class OpenAITransport(unittest.TestCase):
    def test_history_gets_call_ids_and_json_arguments(self):
        history = [
            {"role": "system", "content": "s"},
            {"role": "user", "content": "u"},
            {"role": "assistant", "content": "", "tool_calls": [
                {"function": {"name": "search_attack", "arguments": {"query": "dump lsass"}}},
                {"function": {"name": "lookup_name", "arguments": {"name": "APT29"}}},
            ]},  # fmt: skip
            {"role": "tool", "tool_name": "search_attack", "content": "T1003"},
            {"role": "tool", "tool_name": "lookup_name", "content": "intrusion-set"},
        ]
        out = llm._openai_messages(history)
        calls = out[2]["tool_calls"]
        self.assertEqual([c["id"] for c in calls], ["call_2_0", "call_2_1"])
        self.assertEqual(json.loads(calls[0]["function"]["arguments"]), {"query": "dump lsass"})
        self.assertEqual([m["tool_call_id"] for m in out[3:]], ["call_2_0", "call_2_1"])
        self.assertEqual(llm._openai_messages(history), out)  # sans mémoire : même résultat à chaque tour

    def test_generate_sends_schema_and_deterministic_options(self):
        session = FakeSession(reply('{"entities":"malware|X","behaviors":"3,4"}', usage={"prompt_tokens": 900, "completion_tokens": 12, "prompt_tokens_details": {"cached_tokens": 800}}))
        schema = {"type": "object", "properties": {"entities": {"type": "string"}}}
        with mock.patch.object(llm, "_session", return_value=session):
            r = llm._openai_generate("système", "prompt", schema, 700, "cti-qwen")
        url, body = session.sent[0]
        self.assertTrue(url.endswith("/chat/completions"))
        self.assertEqual((body["temperature"], body["top_k"], body["seed"], body["max_tokens"]), (0, 1, 0, 700))
        self.assertEqual(body["chat_template_kwargs"], {"enable_thinking": False})
        self.assertEqual(body["response_format"]["json_schema"]["schema"], schema)
        self.assertEqual(r.parsed, {"entities": "malware|X", "behaviors": "3,4"})
        self.assertEqual((r.prompt_tokens, r.output_tokens, r.cached_tokens), (900, 12, 800))

    def test_chat_parses_tool_calls_into_ollama_shaped_message(self):
        call = {"id": "c1", "type": "function", "function": {"name": "submit", "arguments": '{"entities": ["malware|X"], "relations": []}'}}
        session = FakeSession(reply(tool_calls=[call]))
        with mock.patch.object(llm, "_session", return_value=session):
            r = llm._openai_chat([{"role": "user", "content": "u"}], [{"type": "function", "function": {"name": "submit"}}], 900, "cti-qwen")
        self.assertEqual(r.tool_calls, [{"name": "submit", "arguments": {"entities": ["malware|X"], "relations": []}}])
        self.assertEqual(r.message["tool_calls"][0]["function"]["arguments"], {"entities": ["malware|X"], "relations": []})
        self.assertFalse(r.truncated)

    def test_truncated_reply_is_flagged(self):
        with mock.patch.object(llm, "_session", return_value=FakeSession(reply("début", finish="length"))):
            self.assertTrue(llm._openai_chat([{"role": "user", "content": "u"}], [], 10, "cti-qwen").truncated)

    def test_http_error_keeps_the_server_message(self):
        with mock.patch.object(llm, "_session", return_value=FakeSession({"error": "schéma refusé"}, status=400)):
            with self.assertRaisesRegex(llm.requests.HTTPError, "schéma refusé"):
                llm._openai_generate("s", "p", {}, 10, "cti-qwen")


if __name__ == "__main__":
    unittest.main()
