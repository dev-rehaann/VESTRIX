"""Command-line entry point for the collector."""

from __future__ import annotations

import argparse
import asyncio
import logging
import signal
from collections.abc import Sequence
from pathlib import Path

from .config import load_config
from .logging import configure_logging
from .server import CollectorServer


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the Vestrix CSI collector")
    parser.add_argument(
        "--config",
        type=Path,
        default=Path("config/collector.yaml"),
        help="collector YAML config path (default: config/collector.yaml)",
    )
    return parser.parse_args(argv)


async def _run(config_path: Path) -> None:
    server = CollectorServer(load_config(config_path))
    await server.start()
    loop = asyncio.get_running_loop()
    reload_task: asyncio.Task[None] | None = None

    async def reload_security_state() -> None:
        try:
            await server.reload_security_state()
        except Exception as exc:
            logging.getLogger("vestrix_collector.decisions").error(
                "collector security-state reload failed",
                extra={
                    "event": "collector_lifecycle",
                    "decision_fields": {
                        "state": "security_state_reload_failed",
                        "error_type": type(exc).__name__,
                    },
                },
            )

    def request_reload() -> None:
        nonlocal reload_task
        if reload_task is None or reload_task.done():
            reload_task = asyncio.create_task(reload_security_state())

    signal_installed = False
    try:
        loop.add_signal_handler(signal.SIGHUP, request_reload)
        signal_installed = True
    except (AttributeError, NotImplementedError):
        pass
    try:
        await asyncio.Event().wait()
    finally:
        if signal_installed:
            loop.remove_signal_handler(signal.SIGHUP)
        if reload_task is not None:
            await reload_task
        await server.close()


def main(argv: Sequence[str] | None = None) -> None:
    """Run the collector until interrupted."""
    args = _parse_args(argv)
    configure_logging()
    try:
        asyncio.run(_run(args.config))
    except KeyboardInterrupt:
        return


if __name__ == "__main__":
    main()
