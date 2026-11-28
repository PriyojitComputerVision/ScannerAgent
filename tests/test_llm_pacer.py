"""LLM calls are paced to the provider's rate limits; a 429 waits exactly what it asks (no network)."""
from __future__ import annotations

import time
from types import SimpleNamespace

import pytest

from pentest_agent import llm, llm_pacer


class Groq429(Exception):
    status_code = 429

    def __init__(self, text="Rate limit reached for model `m` on tokens per minute (TPM): Limit 8000, "
                            "Used 6500, Requested 2400. Please try again in 6.6s.", retry_after="7"):
        super().__init__(f"Error code: 429 - {text}")
        self.response = SimpleNamespace(status_code=429, headers={"retry-after": retry_after})


@pytest.mark.parametrize("text, seconds", [("7.66s", 7.66), ("2m59.56s", 179.56), ("250ms", 0.25),
                                           ("1h2m", 3720.0), ("3", 3.0), ("", None), ("soon", None)])
def test_parse_duration(text, seconds):
    got = llm_pacer.parse_duration(text)
    assert got == pytest.approx(seconds) if seconds is not None else got is None


def test_headers_teach_the_budget_and_pace_a_request_that_does_not_fit():
    llm_pacer.observe_headers("m", {"x-ratelimit-limit-tokens": "8000", "x-ratelimit-remaining-tokens": "1000",
                                    "x-ratelimit-reset-tokens": "5s", "x-ratelimit-remaining-requests": "20"})
    assert llm_pacer.needed_wait("m", 800) == 0.0                      # fits: send now
    wait = llm_pacer.needed_wait("m", 3000)                            # does not fit: wait for the reset
    assert 4.5 < wait <= 5.0 + llm_pacer.CUSHION_SECONDS
    assert llm_pacer.needed_wait("other-model", 3000) == 0.0          # budgets are per model


def test_wait_for_budget_sleeps_then_reserves():
    llm_pacer.observe_headers("m", {"x-ratelimit-limit-tokens": "8000", "x-ratelimit-remaining-tokens": "500",
                                    "x-ratelimit-reset-tokens": "3s"})
    slept, told = [], []
    waited = llm_pacer.wait_for_budget("m", 2000, max_wait=60, notify=told.append, sleep=slept.append)
    assert waited == slept[0] == told[0] and 2.5 < waited < 3.5
    assert llm_pacer.budget("m").tokens_left == 6000                   # window reset, request reserved


def test_a_wait_longer_than_the_budget_raises():
    llm_pacer.observe_headers("m", {"x-ratelimit-remaining-tokens": "0", "x-ratelimit-reset-tokens": "90s"})
    with pytest.raises(TimeoutError):
        llm_pacer.wait_for_budget("m", 100, max_wait=10, sleep=lambda s: None)


def test_429_wait_is_exactly_what_groq_asked_for():
    assert llm_pacer.retry_wait(Groq429(), cap=60) == pytest.approx(7.0)          # retry-after 7 > 6.6s
    assert llm_pacer.retry_wait(Groq429(retry_after="2"), cap=60) == pytest.approx(6.6)
    assert llm_pacer.retry_wait(Groq429(retry_after="300"), cap=60) == 60         # capped


def test_a_429_is_learned_and_its_retry_is_not_paced_twice():
    llm_pacer.observe_429("m", Groq429())
    b = llm_pacer.budget("m")
    assert b.tokens_limit == 8000 and b.tokens_left == 1500
    # the retry right after: tenacity already waited the provider's time, so it is sent at once
    assert llm_pacer.wait_for_budget("m", 5000, max_wait=60, sleep=lambda s: None) == 0.0
    assert llm_pacer.needed_wait("m", 5000) > 0       # but the next call in the same minute is paced


def test_daily_limits_are_not_retried():
    daily = Groq429(text="Rate limit reached on tokens per day (TPD): Limit 500000, Used 499990, Requested 900.")
    assert not llm._is_rate_limit_or_transient(daily)
    assert llm._is_rate_limit_or_transient(Groq429())


def test_summary_calls_reserve_only_what_they_may_return():
    assert llm_pacer.summary_max_tokens(900, 4096) == 300 + llm_pacer.REASONING_HEADROOM
    assert llm_pacer.summary_max_tokens(40000, 4096) == 4096


def test_the_sdk_does_not_retry_and_its_clients_read_the_rate_limit_headers():
    chat = llm.get_llm(max_tokens=900)
    assert chat.max_retries == 0 and chat.max_tokens == 900
    assert llm.get_llm().max_tokens == llm.settings.groq_max_tokens
    client = chat.http_client
    assert client is llm.get_llm().http_client                         # reused per model
    client.event_hooks["response"][0](SimpleNamespace(headers={"x-ratelimit-remaining-tokens": "42",
                                                               "x-ratelimit-reset-tokens": "1s"}))
    assert llm_pacer.budget(llm.settings.groq_model).tokens_left == 42


def test_invoke_paces_before_sending(monkeypatch):
    model = llm.settings.groq_model
    llm_pacer.observe_headers(model, {"x-ratelimit-limit-tokens": "8000", "x-ratelimit-remaining-tokens": "0",
                                      "x-ratelimit-reset-tokens": "2s"})
    slept = []
    monkeypatch.setattr(llm_pacer, "time", SimpleNamespace(monotonic=time.monotonic, sleep=slept.append))
    monkeypatch.setattr(llm_pacer.wait_for_budget, "__defaults__", (None, slept.append))
    sent = []

    class Fake:
        def invoke(self, messages):
            sent.append(messages)
            return "ok"

    assert llm.invoke_with_backoff(Fake(), []) == "ok"
    assert slept and 1.5 < slept[0] < 2.5 and sent == [[]]
