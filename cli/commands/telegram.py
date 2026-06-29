"""CLI command group for Telegram bot operations."""

from __future__ import annotations

import asyncio
import click
import httpx
import time
import logging

from integrations.telegram.handler import get_telegram_token, handle_telegram_message
from integrations.telegram.inbound import parse_telegram_update

logger = logging.getLogger(__name__)


@click.group("telegram")
def telegram_command() -> None:
    """Telegram bot administration and developer utilities."""
    pass


@telegram_command.command("poll")
@click.option(
    "--timeout",
    default=30,
    show_default=True,
    help="Long-polling timeout in seconds.",
)
def telegram_poll_command(timeout: int) -> None:
    """Run the Telegram bot in long-polling mode (local development)."""
    token = get_telegram_token()
    if not token:
        raise click.ClickException(
            "No Telegram bot token configured. "
            "Please export TELEGRAM_BOT_TOKEN or configure the integration."
        )

    click.echo("Starting Telegram bot in long-poll mode...")
    processed_updates: set[int] = set()
    offset = 0

    url = f"https://api.telegram.org/bot{token}/getUpdates"

    async def run_loop():
        nonlocal offset
        async with httpx.AsyncClient() as client:
            while True:
                params = {
                    "timeout": timeout,
                    "offset": offset + 1,
                    "allowed_updates": ["message", "edited_message"],
                }
                try:
                    # Use a slightly longer timeout for httpx to allow long poll to complete
                    response = await client.get(url, params=params, timeout=float(timeout + 5))
                    if response.status_code != 200:
                        click.echo(f"Telegram API returned HTTP {response.status_code}", err=True)
                        await asyncio.sleep(2)
                        continue

                    data = response.json()
                    if not data.get("ok"):
                        click.echo(f"Telegram API error: {data.get('description')}", err=True)
                        await asyncio.sleep(2)
                        continue

                    result = data.get("result", [])
                    for raw in result:
                        if not isinstance(raw, dict):
                            continue
                        update_id = raw.get("update_id")
                        if not isinstance(update_id, int):
                            continue

                        offset = max(offset, update_id)

                        # Deduplicate in-memory to prevent double processing
                        if update_id in processed_updates:
                            continue
                        processed_updates.add(update_id)
                        if len(processed_updates) > 1000:
                            processed_updates.clear()
                            processed_updates.add(update_id)

                        normalized = parse_telegram_update(raw)
                        if normalized is not None:
                            await handle_telegram_message(normalized)

                except httpx.RequestError as exc:
                    click.echo(f"Network error: {exc}", err=True)
                    await asyncio.sleep(2)
                except Exception as exc:
                    click.echo(f"Unexpected error: {exc}", err=True)
                    await asyncio.sleep(2)

    try:
        asyncio.run(run_loop())
    except KeyboardInterrupt:
        click.echo("\nStopping Telegram bot poller.")
