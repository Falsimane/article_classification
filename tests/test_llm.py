"""Transport du client Ollama (sans serveur) : `uv run python -m unittest tests.test_llm -v`."""

import json
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest import mock

from backend.extracting import llm


class FakeSession:
    """Serveur factice : chaque requête dure `seconds` ; compte les requêtes en cours au même instant."""

    def __init__(self, seconds: float):
        self.seconds, self.running, self.peak, self.lock = seconds, 0, 0, threading.Lock()

    def post(self, url, json=None, timeout=None, stream=False):  # noqa: A002 : signature de requests
        session = self

        class Response:
            def __enter__(self):
                with session.lock:
                    session.running += 1
                    session.peak = max(session.peak, session.running)
                return self

            def __exit__(self, *exc):
                with session.lock:
                    session.running -= 1

            def raise_for_status(self):
                pass

            def iter_lines(self):
                time.sleep(session.seconds)
                yield _line({"response": '{"to": "E1"}'})
                yield _line({"done": True, "eval_count": 4})

        return Response()


def _line(obj) -> bytes:
    return json.dumps(obj).encode()


class Parse(unittest.TestCase):
    def test_a_truncated_answer_keeps_its_complete_elements(self):
        self.assertEqual(llm._parse('{"relations": ["12a:uses", "13b:tar'), {"relations": ["12a:uses"]})  # aucun crochet fermant
        self.assertEqual(llm._parse('{"entities": ["malware|Emotet", "tool|Cobal'), {"entities": ["malware|Emotet"]})  # pas d'entité « Cobal »
        self.assertEqual(llm._parse('<think>x</think>{"a": [1, 2]} fin'), {"a": [1, 2]})
        self.assertIsNone(llm._parse("aucun JSON"))


class Slots(unittest.TestCase):
    def run_calls(self, slots: int, n: int, seconds: float, timeout: float) -> tuple[FakeSession, list[llm.LLMResult]]:
        fake = FakeSession(seconds)
        with mock.patch.object(llm, "_session", return_value=fake), mock.patch.object(llm, "_slots", threading.BoundedSemaphore(slots)), mock.patch.object(llm, "TOTAL_REQUEST_TIMEOUT", timeout):
            with ThreadPoolExecutor(max_workers=n) as pool:
                results = list(pool.map(lambda _: llm.try_generate("s", "p", {}), range(n)))
        return fake, results

    def test_never_more_requests_in_flight_than_server_slots(self):
        fake, results = self.run_calls(slots=2, n=6, seconds=0.05, timeout=5)
        self.assertEqual(fake.peak, 2)
        self.assertTrue(all(r.parsed == {"to": "E1"} and r.error is None for r in results))

    def test_waiting_for_a_slot_does_not_count_against_the_timeout(self):
        # 4 requêtes de 0,15 s sur un slot : la dernière attend 0,45 s, au-delà du délai de 0,3 s, sans être abandonnée
        fake, results = self.run_calls(slots=1, n=4, seconds=0.15, timeout=0.3)
        self.assertEqual(fake.peak, 1)
        self.assertEqual([r.error for r in results], [None] * 4)


if __name__ == "__main__":
    unittest.main()
