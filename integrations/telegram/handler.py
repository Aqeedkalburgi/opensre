"""Handler for Telegram inbound commands and security checks."""

from __future__ import annotations

import json
import logging
import hashlib
from typing import Any
import asyncio

from integrations.messaging_security import (
    authorize_inbound_message,
    complete_pairing,
    MessagingIdentityPolicy,
    MessagingPlatform,
    audit_log_inbound_message,
)
from integrations.store import get_integration, upsert_instance
from integrations.telegram.inbound import NormalizedMessage
from platform.notifications.telegram_delivery import post_telegram_message

logger = logging.getLogger(__name__)

# Keep strong references to background tasks to prevent garbage collection on Python 3.11+
_background_tasks: set[asyncio.Task[None]] = set()


def _load_policy() -> tuple[dict | None, MessagingIdentityPolicy]:
    record = get_integration(MessagingPlatform.TELEGRAM.value)
    if record is None:
        return None, MessagingIdentityPolicy(inbound_enabled=True)
    credentials = record.get("credentials", {})
    raw_policy = credentials.get("identity_policy")
    if raw_policy and isinstance(raw_policy, dict):
        return record, MessagingIdentityPolicy.model_validate(raw_policy)
    return record, MessagingIdentityPolicy(inbound_enabled=True)


def _save_policy(record: dict | None, policy: MessagingIdentityPolicy) -> None:
    instances = record.get("instances", []) if record else []
    first_instance = instances[0] if instances else {}
    instance_name = (
        first_instance.get("name", "default") if isinstance(first_instance, dict) else "default"
    )
    credentials = dict(record.get("credentials", {})) if record else {}
    credentials["identity_policy"] = policy.model_dump(mode="json")
    upsert_instance(
        MessagingPlatform.TELEGRAM.value,
        {
            "name": instance_name,
            "tags": first_instance.get("tags", {}) if isinstance(first_instance, dict) else {},
            "credentials": credentials,
        },
        record_id=record.get("id") if record else None,
    )


def _message_hash(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()[:16]


def get_telegram_token() -> str:
    """Load Telegram bot token."""
    import os
    token = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
    if not token:
        record = get_integration(MessagingPlatform.TELEGRAM.value)
        if record:
            creds = record.get("credentials", {})
            token = str(creds.get("bot_token") or "").strip()
    return token


async def handle_telegram_message(message: NormalizedMessage) -> None:
    """Evaluate authorization, run commands, and execute investigations in the background."""
    token = get_telegram_token()
    if not token:
        logger.error("[telegram-handler] No Telegram bot token configured.")
        return

    record, policy = _load_policy()

    # 1. Check Inbound enabled?
    if not policy.inbound_enabled:
        audit_log_inbound_message(
            platform="telegram",
            user_id=message.user_id,
            chat_id=message.chat_id,
            message_hash=_message_hash(message.text),
            authorized=False,
            reason="Inbound messaging is not enabled for this platform",
        )
        post_telegram_message(
            chat_id=message.chat_id,
            text="Inbound messaging is not enabled for this platform",
            bot_token=token,
            reply_to_message_id=message.message_id,
        )
        return

    # 2. Check Authorization / Pairing attempt
    auth_result = authorize_inbound_message(
        policy=policy,
        user_id=message.user_id,
        chat_id=message.chat_id,
        message_text=message.text,
    )

    audit_log_inbound_message(
        platform="telegram",
        user_id=message.user_id,
        chat_id=message.chat_id,
        message_hash=_message_hash(message.text),
        authorized=bool(auth_result),
        reason=auth_result.reason,
    )

    if not auth_result:
        # User is not authorized
        post_telegram_message(
            chat_id=message.chat_id,
            text=auth_result.reason,
            bot_token=token,
            reply_to_message_id=message.message_id,
        )
        return

    # Handle commands
    text = message.text.strip()
    parts = text.split(maxsplit=1)
    cmd = parts[0].lower() if parts else ""
    args = parts[1].strip() if len(parts) > 1 else ""

    # /pair command
    if cmd == "/pair":
        ok, reply_text = complete_pairing(policy=policy, user_id=message.user_id, code=args)
        _save_policy(record, policy)
        post_telegram_message(
            chat_id=message.chat_id,
            text=reply_text,
            bot_token=token,
            reply_to_message_id=message.message_id,
        )
        return

    # User must be fully paired/authorized beyond this point
    if message.user_id not in policy.allowed_user_ids:
        post_telegram_message(
            chat_id=message.chat_id,
            text="Please complete pairing first using /pair <code>.",
            bot_token=token,
            reply_to_message_id=message.message_id,
        )
        return

    if cmd == "/help":
        help_text = (
            "Available commands:\n"
            "/pair <code> - Complete pairing with the bot\n"
            "/investigate <alert> - Start an investigation (supports text or JSON)\n"
            "/status <id> - Check investigation status\n"
            "/help - Show this help message"
        )
        post_telegram_message(
            chat_id=message.chat_id,
            text=help_text,
            bot_token=token,
            reply_to_message_id=message.message_id,
        )
        return

    elif cmd == "/status":
        if not args:
            post_telegram_message(
                chat_id=message.chat_id,
                text="Usage: /status <investigation_id>",
                bot_token=token,
                reply_to_message_id=message.message_id,
            )
            return

        from core.agent_harness.session import DEFAULT_SESSION_REPO
        inv, count = DEFAULT_SESSION_REPO.lookup_investigation(args)
        if count == 0:
            status_text = f"No investigation found matching '{args}'."
        elif count > 1:
            status_text = f"Multiple investigations ({count}) match prefix '{args}'."
        else:
            alert_name = inv.get("alert_name") or "Unknown Alert"
            category = inv.get("root_cause_category") or "None"
            root_cause = inv.get("root_cause") or "None"
            status = inv.get("status") or "Completed"
            status_text = (
                f"Investigation Status: {status}\n"
                f"Alert: {alert_name}\n"
                f"Category: {category}\n"
                f"Root Cause: {root_cause}"
            )
        post_telegram_message(
            chat_id=message.chat_id,
            text=status_text,
            bot_token=token,
            reply_to_message_id=message.message_id,
        )
        return

    elif cmd == "/investigate":
        if not args:
            post_telegram_message(
                chat_id=message.chat_id,
                text="Usage: /investigate <text alert or JSON payload>",
                bot_token=token,
                reply_to_message_id=message.message_id,
            )
            return

        # Attempt to parse as JSON first
        alert_payload: str | dict[str, Any] = args
        try:
            parsed = json.loads(args)
            if isinstance(parsed, dict):
                alert_payload = parsed
        except Exception:
            pass

        # Send acknowledgement
        post_telegram_message(
            chat_id=message.chat_id,
            text="Investigation started in the background...",
            bot_token=token,
            reply_to_message_id=message.message_id,
        )

        # Run in background with strong reference to prevent GC
        task = asyncio.create_task(
            _background_investigation(
                alert_payload=alert_payload,
                chat_id=message.chat_id,
                message_id=message.message_id,
                bot_token=token,
            )
        )
        _background_tasks.add(task)
        task.add_done_callback(_background_tasks.discard)
        return

    else:
        # Invalid command
        post_telegram_message(
            chat_id=message.chat_id,
            text="Unknown command. Type /help for available commands.",
            bot_token=token,
            reply_to_message_id=message.message_id,
        )


async def _background_investigation(
    alert_payload: str | dict[str, Any],
    chat_id: str,
    message_id: str,
    bot_token: str,
) -> None:
    from tools.investigation.capability import run_investigation_payload

    try:
        await asyncio.to_thread(
            run_investigation_payload,
            raw_alert=alert_payload,
            telegram_context={
                "chat_id": chat_id,
                "reply_to_message_id": message_id,
                "bot_token": bot_token,
            },
        )
    except Exception as exc:
        logger.exception("[telegram-handler] Investigation failed: %s", exc)
        post_telegram_message(
            chat_id=chat_id,
            text="An internal error occurred during the investigation. Please check the logs for details.",
            bot_token=bot_token,
            reply_to_message_id=message_id,
        )
