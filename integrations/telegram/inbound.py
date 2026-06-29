"""Telegram Inbound Adapter for parsing updates into normalized messages."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class NormalizedMessage:
    """Normalized inbound messaging platform representation."""

    platform: str
    chat_id: str
    user_id: str
    message_id: str
    reply_to_message_id: str | None
    text: str
    update_id: int


def parse_telegram_update(update: dict[str, Any]) -> NormalizedMessage | None:
    """Safely parse a Telegram update dictionary into a NormalizedMessage."""
    if not isinstance(update, dict):
        return None

    update_id = update.get("update_id")
    if not isinstance(update_id, int):
        return None

    # Handle standard messages and edited messages
    message = update.get("message") or update.get("edited_message")
    if not isinstance(message, dict):
        return None

    from_user = message.get("from")
    if not isinstance(from_user, dict):
        return None

    user_id = str(from_user.get("id") or "")
    if not user_id:
        return None

    chat = message.get("chat")
    if not isinstance(chat, dict):
        return None

    chat_id = str(chat.get("id") or "")
    if not chat_id:
        return None

    message_id = str(message.get("message_id") or "")
    text = message.get("text")
    if not isinstance(text, str):
        text = ""

    reply_to = message.get("reply_to_message")
    reply_to_message_id = None
    if isinstance(reply_to, dict):
        reply_to_message_id = str(reply_to.get("message_id") or "")

    return NormalizedMessage(
        platform="telegram",
        chat_id=chat_id,
        user_id=user_id,
        message_id=message_id,
        reply_to_message_id=reply_to_message_id,
        text=text,
        update_id=update_id,
    )
