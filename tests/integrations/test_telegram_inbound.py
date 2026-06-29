"""Tests for Telegram inbound integration - parsing, webhook, polling, and security."""

from __future__ import annotations

import os
import json
import time
import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

from config.webapp import app
from integrations.telegram.inbound import parse_telegram_update
from integrations.telegram.handler import handle_telegram_message
from integrations.messaging_security import MessagingIdentityPolicy, hash_pairing_code


# ---------------------------------------------------------------------------
# Inbound Adapter (Parsing) Tests
# ---------------------------------------------------------------------------

def test_parse_telegram_update_dm() -> None:
    payload = {
        "update_id": 10001,
        "message": {
            "message_id": 42,
            "from": {"id": 12345, "is_bot": False, "first_name": "Test"},
            "chat": {"id": 12345, "type": "private"},
            "text": "hello bot",
        },
    }
    parsed = parse_telegram_update(payload)
    assert parsed is not None
    assert parsed.platform == "telegram"
    assert parsed.update_id == 10001
    assert parsed.user_id == "12345"
    assert parsed.chat_id == "12345"
    assert parsed.message_id == "42"
    assert parsed.text == "hello bot"
    assert parsed.reply_to_message_id is None


def test_parse_telegram_update_group() -> None:
    payload = {
        "update_id": 10002,
        "message": {
            "message_id": 43,
            "from": {"id": 12345, "is_bot": False, "first_name": "Test"},
            "chat": {"id": -98765, "type": "group"},
            "text": "/help",
        },
    }
    parsed = parse_telegram_update(payload)
    assert parsed is not None
    assert parsed.chat_id == "-98765"
    assert parsed.user_id == "12345"


def test_parse_telegram_update_missing_text() -> None:
    payload = {
        "update_id": 10003,
        "message": {
            "message_id": 44,
            "from": {"id": 12345, "is_bot": False, "first_name": "Test"},
            "chat": {"id": 12345, "type": "private"},
        },
    }
    parsed = parse_telegram_update(payload)
    assert parsed is not None
    assert parsed.text == ""


def test_parse_telegram_update_reply() -> None:
    payload = {
        "update_id": 10004,
        "message": {
            "message_id": 45,
            "from": {"id": 12345, "is_bot": False, "first_name": "Test"},
            "chat": {"id": 12345, "type": "private"},
            "text": "yes",
            "reply_to_message": {
                "message_id": 40,
                "text": "Are you sure?",
            },
        },
    }
    parsed = parse_telegram_update(payload)
    assert parsed is not None
    assert parsed.reply_to_message_id == "40"


def test_parse_telegram_update_bad_payload() -> None:
    assert parse_telegram_update({}) is None
    assert parse_telegram_update({"update_id": "not-an-int"}) is None
    assert parse_telegram_update({"update_id": 1, "message": "not-a-dict"}) is None


# ---------------------------------------------------------------------------
# Pairing & Authorization Tests
# ---------------------------------------------------------------------------

@patch("integrations.telegram.handler.get_integration")
@patch("integrations.telegram.handler.post_telegram_message")
def test_handler_disabled_inbound(mock_post: MagicMock, mock_get: MagicMock) -> None:
    mock_get.return_value = {
        "credentials": {
            "bot_token": "fake-token",
            "identity_policy": MessagingIdentityPolicy(inbound_enabled=False).model_dump(mode="json"),
        }
    }
    msg = parse_telegram_update({
        "update_id": 1,
        "message": {
            "message_id": 10,
            "from": {"id": 123, "first_name": "User"},
            "chat": {"id": 123, "type": "private"},
            "text": "/help",
        }
    })
    assert msg is not None
    # Run handler
    import asyncio
    asyncio.run(handle_telegram_message(msg))
    mock_post.assert_called_once_with(
        chat_id="123",
        text="Inbound messaging is not enabled for this platform",
        bot_token="fake-token",
        reply_to_message_id="10",
    )


@patch("integrations.telegram.handler.get_integration")
@patch("integrations.telegram.handler.post_telegram_message")
def test_handler_unpaired_user_rejects(mock_post: MagicMock, mock_get: MagicMock) -> None:
    mock_get.return_value = {
        "credentials": {
            "bot_token": "fake-token",
            "identity_policy": MessagingIdentityPolicy(
                inbound_enabled=True,
                require_dm_pairing=True,
                allowed_user_ids=[],
            ).model_dump(mode="json"),
        }
    }
    msg = parse_telegram_update({
        "update_id": 1,
        "message": {
            "message_id": 10,
            "from": {"id": 123, "first_name": "User"},
            "chat": {"id": 123, "type": "private"},
            "text": "/help",
        }
    })
    assert msg is not None
    import asyncio
    asyncio.run(handle_telegram_message(msg))
    assert any("pair" in (call.kwargs.get("text") or "").lower() for call in mock_post.mock_calls)


@patch("integrations.telegram.handler.get_integration")
@patch("integrations.telegram.handler.post_telegram_message")
@patch("integrations.telegram.handler.upsert_instance")
def test_pairing_flow(mock_upsert: MagicMock, mock_post: MagicMock, mock_get: MagicMock) -> None:
    code = "XYZ123"
    hashed = hash_pairing_code(code)
    policy = MessagingIdentityPolicy(
        inbound_enabled=True,
        require_dm_pairing=True,
        pairing_secret_hash=hashed,
        pairing_created_at=time.time(),
        pairing_attempts=0,
    )
    mock_get.return_value = {
        "credentials": {
            "bot_token": "fake-token",
            "identity_policy": policy.model_dump(mode="json"),
        }
    }

    # 1. Invalid code
    msg = parse_telegram_update({
        "update_id": 1,
        "message": {
            "message_id": 10,
            "from": {"id": 123, "first_name": "User"},
            "chat": {"id": 123, "type": "private"},
            "text": "/pair WRONGCODE",
        }
    })
    import asyncio
    asyncio.run(handle_telegram_message(msg))
    mock_post.assert_any_call(
        chat_id="123",
        text="Invalid pairing code. 4 attempts remaining.",
        bot_token="fake-token",
        reply_to_message_id="10",
    )

    # Update policy mock to reflect the attempt
    policy.pairing_attempts = 1
    mock_get.return_value["credentials"]["identity_policy"] = policy.model_dump(mode="json")

    # 2. Correct code
    msg = parse_telegram_update({
        "update_id": 2,
        "message": {
            "message_id": 11,
            "from": {"id": 123, "first_name": "User"},
            "chat": {"id": 123, "type": "private"},
            "text": f"/pair {code}",
        }
    })
    asyncio.run(handle_telegram_message(msg))
    mock_post.assert_any_call(
        chat_id="123",
        text="Pairing successful! You can now interact with the bot.",
        bot_token="fake-token",
        reply_to_message_id="11",
    )
    mock_upsert.assert_called()


# ---------------------------------------------------------------------------
# Webhook Web Layer Tests
# ---------------------------------------------------------------------------

def test_webhook_secret_verification() -> None:
    client = TestClient(app)
    os.environ["TELEGRAM_WEBHOOK_SECRET"] = "super-secret-token"

    try:
        # Forbidden without secret token
        resp = client.post("/telegram/webhook", json={})
        assert resp.status_code == 403

        # Forbidden with incorrect secret token
        resp = client.post(
            "/telegram/webhook",
            json={},
            headers={"X-Telegram-Bot-Api-Secret-Token": "wrong-secret"},
        )
        assert resp.status_code == 403

        # Allowed with correct token
        with patch("config.webapp.handle_telegram_message") as mock_handle:
            resp = client.post(
                "/telegram/webhook",
                json={
                    "update_id": 55,
                    "message": {
                        "message_id": 1,
                        "from": {"id": 999},
                        "chat": {"id": 999},
                        "text": "/help",
                    },
                },
                headers={"X-Telegram-Bot-Api-Secret-Token": "super-secret-token"},
            )
            assert resp.status_code == 200
            assert mock_handle.called

    finally:
        os.environ.pop("TELEGRAM_WEBHOOK_SECRET", None)


# ---------------------------------------------------------------------------
# Polling transport tests
# ---------------------------------------------------------------------------

@patch("integrations.telegram.handler.get_telegram_token")
@patch("integrations.telegram.handler.handle_telegram_message")
def test_polling_duplicate_update_id_ignored(mock_handle: MagicMock, mock_token: MagicMock) -> None:
    mock_token.return_value = "fake-token"

    # Mock httpx response to return two updates, one is duplicate
    updates = [
        {
            "update_id": 100,
            "message": {
                "message_id": 1,
                "from": {"id": 999},
                "chat": {"id": 999},
                "text": "first",
            },
        },
        {
            "update_id": 100,  # duplicate update_id
            "message": {
                "message_id": 2,
                "from": {"id": 999},
                "chat": {"id": 999},
                "text": "second",
            },
        },
        {
            "update_id": 101,
            "message": {
                "message_id": 3,
                "from": {"id": 999},
                "chat": {"id": 999},
                "text": "third",
            },
        },
    ]

    # We will invoke the polling logic inside the loop manually by injecting the updates.
    # We can mock client.get to return updates.
    # To test deduplication, we can check that only 100 and 101 are handled.
    from click.testing import CliRunner
    from cli.commands.telegram import telegram_poll_command

    # Let's mock httpx.AsyncClient.get to return the updates list
    class MockResponse:
        def __init__(self, data):
            self.status_code = 200
            self._data = data

        def json(self):
            return {"ok": True, "result": self._data}

    # We patch run_loop's execution or just mock AsyncClient
    # To make it terminate, we will raise an exception inside the loop after the first call.
    call_count = 0

    async def mock_get(*args, **kwargs):
        nonlocal call_count
        if call_count == 0:
            call_count += 1
            return MockResponse(updates)
        raise KeyboardInterrupt()

    with patch("httpx.AsyncClient.get", side_effect=mock_get):
        runner = CliRunner()
        # Run poll command (timeout set to small value)
        runner.invoke(telegram_poll_command, ["--timeout", "1"])
        
        # We expect handle_telegram_message to be called only for update_id 100 (first) and 101
        assert mock_handle.call_count == 2
        calls = mock_handle.mock_calls
        assert calls[0][1][0].update_id == 100
        assert calls[0][1][0].text == "first"
        assert calls[1][1][0].update_id == 101
        assert calls[1][1][0].text == "third"
