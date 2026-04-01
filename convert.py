"""CLI entrypoint for ScreenOS-to-Junos conversion."""

from __future__ import annotations

import argparse
import logging
import time
from datetime import datetime
from pathlib import Path

from packages.converter_core import Converter

LOGGER = logging.getLogger(__name__)


def build_output_path(requested_output: str | None) -> Path:
    if requested_output:
        return Path(requested_output)

    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    return Path('outputs') / f'converted_{timestamp}.txt'


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Convert ScreenOS firewall config snippets into Junos SRX syntax.",
    )
    parser.add_argument(
        "--input",
        default="input/netscreen_config.txt",
        help="Input ScreenOS configuration file (default: input/netscreen_config.txt)",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Output file path (default: outputs/converted_<timestamp>.txt)",
    )
    parser.add_argument(
        "--progress-interval",
        type=int,
        default=100,
        help="Log progress every N lines while parsing (default: 100)",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging level (default: INFO)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    logging.basicConfig(level=getattr(logging, args.log_level), format="%(message)s")

    input_path = Path(args.input)
    output_path = build_output_path(args.output)

    if not input_path.is_file():
        LOGGER.error("Input file does not exist: %s", input_path)
        return 1

    start_time = time.perf_counter()

    converter = Converter(progress_interval=args.progress_interval)
    converter.read_file(input_path)
    converter.disabled_rule_cleanup()
    converter.converted_config_output(output_path)

    elapsed = time.perf_counter() - start_time
    LOGGER.info("number of lines converted: %s", converter.state.succeeded)
    LOGGER.info("number of lines NOT converted: %s", converter.state.failed)
    LOGGER.info("output file: %s", output_path)
    LOGGER.info("Total Runtime: %.4f seconds", elapsed)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
