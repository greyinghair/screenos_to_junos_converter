"""CLI entrypoint for ScreenOS-to-Junos conversion."""

from __future__ import annotations

import argparse
import json
import logging
import time
from datetime import datetime
from pathlib import Path

from packages.conversion_models import (
    InterfaceMappingError,
    InterfaceMappingRequest,
    ResolvedInterfaceMapping,
    resolve_interface_mappings,
)
from packages.converter_core import Converter
from packages.interface_inventory import build_interface_inventory

LOGGER = logging.getLogger(__name__)
MAPPING_FIELDS = frozenset(
    {"screenos_name", "physical_name", "unit", "vlan_mode", "vlan_id"}
)


def load_interface_mappings(path: Path) -> dict[str, ResolvedInterfaceMapping]:
    """Read and validate the optional JSON interface-mapping file."""

    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise InterfaceMappingError(f"{path} is not readable JSON") from exc
    if not isinstance(document, list):
        raise InterfaceMappingError(f"{path} must contain a list of mappings")

    requests: list[InterfaceMappingRequest] = []
    for entry in document:
        if not isinstance(entry, dict):
            raise InterfaceMappingError(f"{path} contains a non-object mapping")
        unknown = sorted(set(entry) - MAPPING_FIELDS)
        if unknown:
            raise InterfaceMappingError(
                f"{path} contains unsupported mapping fields: {', '.join(unknown)}"
            )
        try:
            requests.append(
                InterfaceMappingRequest(
                    screenos_name=str(entry["screenos_name"]),
                    physical_name=str(entry["physical_name"]),
                    unit=int(entry.get("unit", 0)),
                    vlan_mode=entry.get("vlan_mode", "access"),
                    vlan_id=(
                        None if entry.get("vlan_id") is None else int(entry["vlan_id"])
                    ),
                )
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise InterfaceMappingError(f"{path} contains a malformed mapping") from exc
    return resolve_interface_mappings(requests)


def build_output_path(requested_output: str | None) -> Path:
    if requested_output:
        return Path(requested_output)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return Path("outputs") / f"converted_{timestamp}.txt"


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
        "--interface-map",
        default=None,
        help=(
            "Optional JSON file of approved ScreenOS-to-Junos interface mappings. "
            "Without it the default interface-name strategy is used."
        ),
    )
    parser.add_argument(
        "--interface-inventory",
        default=None,
        help="Optional path to write the JSON interface binding inventory",
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

    interface_mappings: dict[str, ResolvedInterfaceMapping] = {}
    if args.interface_map:
        try:
            interface_mappings = load_interface_mappings(Path(args.interface_map))
        except InterfaceMappingError as exc:
            LOGGER.error("Invalid interface mapping: %s", exc)
            return 1

    start_time = time.perf_counter()

    converter = Converter(
        progress_interval=args.progress_interval,
        interface_mappings=interface_mappings,
    )
    converter.read_file(input_path)
    converter.disabled_rule_cleanup()
    converter.converted_config_output(output_path)

    if args.interface_inventory:
        inventory_path = Path(args.interface_inventory)
        inventory_path.parent.mkdir(parents=True, exist_ok=True)
        inventory_path.write_text(
            json.dumps(
                build_interface_inventory(converter.state).as_dict(),
                indent=2,
                sort_keys=False,
            )
            + "\n",
            encoding="utf-8",
        )

    elapsed = time.perf_counter() - start_time
    for diagnostic in converter.state.diagnostics:
        location = (
            f"line {diagnostic.line_number}"
            if diagnostic.line_number is not None
            else "unknown line"
        )
        LOGGER.warning("%s not converted: %s", location, diagnostic.reason)
    for warning in converter.state.manual_review_warnings:
        LOGGER.warning("MANUAL REVIEW REQUIRED: %s", warning)
    for screenos_name, applied in sorted(
        converter.state.applied_interface_mappings.items()
    ):
        LOGGER.info(
            "applied interface mapping: %s -> %s", screenos_name, applied.summary
        )
    LOGGER.info("number of lines converted: %s", converter.state.succeeded)
    LOGGER.info("number of lines NOT converted: %s", converter.state.failed)
    LOGGER.info("output file: %s", output_path)
    LOGGER.info("Total Runtime: %.4f seconds", elapsed)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
