#!/usr/bin/env python3

from __future__ import annotations

import argparse
import math
import sys
from dataclasses import dataclass
from typing import Any, Optional
from urllib.parse import quote

import requests
from requests.auth import HTTPBasicAuth

import re
import unicodedata


def sanitize_perfdata_name(name: str, max_length: int = 200) -> str:
    """
    Sanitize a perfdata label.

    - normalize unicode
    - replace whitespace with underscores
    - remove single quotes (escaped differently in perfdata)
    - replace characters outside a safe set with underscores
    - collapse repeated underscores
    """

    # Normalize unicode representation
    name = unicodedata.normalize("NFKC", name)

    # Replace whitespace with underscores
    name = re.sub(r"\s+", "_", name)
    name = name.replace("/","_")
    name = name.lower()
    # Remove single quotes
    name = name.replace("'", "")

    # Keep only a conservative set of characters
    name = re.sub(r"[^A-Za-z0-9._/\-]", "_", name)

    # Collapse duplicate underscores
    name = re.sub(r"_+", "_", name)

    # Remove leading/trailing separators
    name = name.strip("_")

    return name[:max_length]

ThresholdDict = dict[str, dict[str, Optional[str]]]


@dataclass(frozen=True)
class IcingaRange:
    """
    Nagios/Icinga threshold range.

    Normal ranges alert when the value is outside the range.
    @ ranges alert when the value is inside the range.
    """

    start: float
    end: float
    inverted: bool = False

    def contains(self, value: float) -> bool:
        return self.start <= value <= self.end

    def is_alert(self, value: float) -> bool:
        inside = self.contains(value)
        return inside if self.inverted else not inside


def parse_icinga_range(expression: str) -> IcingaRange:
    """
    Parse Icinga/Nagios ranges.

    Supported examples:
        0:10
        @0:10
        :10
        10:
        10
        ~:10
    """
    expression = expression.strip()

    if not expression:
        raise ValueError("Range must not be empty.")

    inverted = expression.startswith("@")
    if inverted:
        expression = expression[1:]

    if not expression:
        raise ValueError("Missing range after '@'.")

    if ":" in expression:
        if expression.count(":") != 1:
            raise ValueError(
                f"Invalid range {expression!r}: only one ':' is allowed."
            )

        start_text, end_text = expression.split(":", 1)

        # Empty start means zero according to plugin range syntax.
        if start_text == "":
            start = 0.0
        elif start_text == "~":
            start = -math.inf
        else:
            start = parse_range_number(start_text)

        # Empty end means positive infinity.
        if end_text == "":
            end = math.inf
        elif end_text == "~":
            raise ValueError(
                f"Invalid range {expression!r}: '~' is only valid as the start."
            )
        else:
            end = parse_range_number(end_text)

    else:
        # A single number means 0:number.
        start = 0.0
        end = parse_range_number(expression)

    if start > end:
        raise ValueError(
            f"Invalid range {expression!r}: start must not exceed end."
        )

    return IcingaRange(
        start=start,
        end=end,
        inverted=inverted,
    )


def parse_range_number(value: str) -> float:
    try:
        number = float(value)
    except ValueError as exc:
        raise ValueError(
            f"Invalid numeric range boundary {value!r}."
        ) from exc

    if not math.isfinite(number):
        raise ValueError(
            f"Range boundary {value!r} must be finite."
        )

    return number


def critical_out_of_range(
    value: float,
    critical_range: str | None,
) -> bool:
    """
    Return True when the value is critical according to an Icinga range.
    """
    if critical_range is None:
        return False

    return parse_icinga_range(critical_range).is_alert(value)


def warning_out_of_range(
    value: float,
    warning_range: str | None,
) -> bool:
    """
    Return True when the value is warning according to an Icinga range.
    """
    if warning_range is None:
        return False

    return parse_icinga_range(warning_range).is_alert(value)


def evaluate_sensor(
    value: float,
    thresholds: dict[str, str | None],
) -> str:
    """
    Critical is evaluated before warning.
    """
    if critical_out_of_range(value, thresholds.get("critical")):
        return "CRITICAL"

    if warning_out_of_range(value, thresholds.get("warning")):
        return "WARNING"

    return "OK"


def validate_entity(entity: str) -> str:
    entity = entity.strip()

    if "/" not in entity:
        raise argparse.ArgumentTypeError(
            f"Invalid entity {entity!r}; expected domain/sensorname."
        )

    domain, name = entity.split("/", 1)

    if not domain or not name:
        raise argparse.ArgumentTypeError(
            f"Invalid entity {entity!r}; expected domain/sensorname."
        )

    return entity


def parse_threshold_argument(value: str) -> tuple[str, str]:
    """
    Parse:

        domain/sensorname->icinga-range
    """
    entity, separator, range_expression = value.rpartition("->")

    if not separator:
        raise argparse.ArgumentTypeError(
            f"Invalid threshold {value!r}; expected "
            "domain/sensorname->range."
        )

    entity = validate_entity(entity)
    range_expression = range_expression.strip()

    try:
        parse_icinga_range(range_expression)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            f"Invalid threshold for {entity!r}: {exc}"
        ) from exc

    return entity, range_expression


def build_thresholds(
    sensors: list[str],
    warnings: list[tuple[str, str]],
    criticals: list[tuple[str, str]],
) -> ThresholdDict:
    thresholds: ThresholdDict = {
        sensor: {
            "warning": None,
            "critical": None,
        }
        for sensor in sensors
    }

    for entity, threshold_range in warnings:
        if entity not in thresholds:
            raise ValueError(
                f"Warning configured for {entity!r}, but the entity "
                "was not supplied with --sensor."
            )

        thresholds[entity]["warning"] = threshold_range

    for entity, threshold_range in criticals:
        if entity not in thresholds:
            raise ValueError(
                f"Critical configured for {entity!r}, but the entity "
                "was not supplied with --sensor."
            )

        thresholds[entity]["critical"] = threshold_range

    return thresholds


def query_entity(
    session: requests.Session,
    base_url: str,
    entity: str,
    timeout: float,
) -> dict[str, Any]:
    domain, sensor_name = entity.split("/", 1)

    # This converts spaces to %20 and safely encodes other URL characters.
    encoded_name = quote(sensor_name, safe="")
    url = f"{base_url.rstrip('/')}/{domain}/{encoded_name}"

    try:
        response = session.get(url, timeout=timeout)

        if response.status_code == 401:
            raise RuntimeError(
                "Authentication failed: check username and password."
            )

        if response.status_code == 404:
            raise RuntimeError(f"Entity {entity!r} was not found.")

        response.raise_for_status()

        payload = response.json()

        if not isinstance(payload, dict):
            raise RuntimeError(
                f"Unexpected response type for {entity!r}."
            )

        return payload

    except requests.exceptions.JSONDecodeError as exc:
        raise RuntimeError(
            f"ESPHome returned invalid JSON for {entity!r}."
        ) from exc
    except requests.exceptions.Timeout as exc:
        raise RuntimeError(
            f"Request for {entity!r} timed out."
        ) from exc
    except requests.exceptions.ConnectionError as exc:
        raise RuntimeError(
            f"Could not connect to {base_url}: {exc}"
        ) from exc
    except requests.exceptions.RequestException as exc:
        raise RuntimeError(
            f"Request for {entity!r} failed: {exc}"
        ) from exc


def get_numeric_value(payload: dict[str, Any]) -> float:
    """
    ESPHome response example:

        {
            "name_id": "sensor/Inkbird IHT-2PB probe 1",
            "id": "sensor-inkbird_iht-2pb_probe_1",
            "value": 27.9,
            "state": "27.9 °C"
        }

    Prefer the numeric 'value' field.
    """
    value = payload.get("value")

    if isinstance(value, bool):
        return float(value)

    if isinstance(value, (int, float)):
        result = float(value)

        if not math.isfinite(result):
            raise RuntimeError("Sensor returned a non-finite value.")

        return result

    if isinstance(value, str):
        try:
            result = float(value)
        except ValueError as exc:
            raise RuntimeError(
                f"Sensor value {value!r} is not numeric."
            ) from exc

        if not math.isfinite(result):
            raise RuntimeError("Sensor returned a non-finite value.")

        return result

    raise RuntimeError(
        "ESPHome response does not contain a numeric 'value' field."
    )


def format_perfdata_label(entity: str) -> str:
    return sanitize_perfdata_name(entity)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Check selected ESPHome sensors using Icinga ranges."
    )

    parser.add_argument("--url", required=True)
    parser.add_argument("--title", default="ESPHome sensor check")
    parser.add_argument("--username", required=True)
    parser.add_argument("--password", required=True)

    parser.add_argument(
        "--sensor",
        action="append",
        type=validate_entity,
        required=True,
        metavar="DOMAIN/SENSORNAME",
    )

    parser.add_argument(
        "--warning",
        action="append",
        type=parse_threshold_argument,
        default=[],
        metavar="DOMAIN/SENSORNAME->RANGE",
    )

    parser.add_argument(
        "--critical",
        action="append",
        type=parse_threshold_argument,
        default=[],
        metavar="DOMAIN/SENSORNAME->RANGE",
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
    )

    parser.add_argument(
        "--no-perfdata",
        action="store_true",
    )

    args = parser.parse_args()

    sensors = list(dict.fromkeys(args.sensor))

    try:
        thresholds = build_thresholds(
            sensors=sensors,
            warnings=args.warning,
            criticals=args.critical,
        )
    except ValueError as exc:
        parser.error(str(exc))

    session = requests.Session()
    session.auth = HTTPBasicAuth(args.username, args.password)
    session.headers.update({"Accept": "application/json"})

    overall_code = 0
    messages: list[str] = []
    perfdata: list[str] = []

    for entity in sensors:
        warning = thresholds[entity]["warning"]
        critical = thresholds[entity]["critical"]

        try:
            payload = query_entity(
                session=session,
                base_url=args.url,
                entity=entity,
                timeout=args.timeout,
            )

            value = get_numeric_value(payload)
            state = evaluate_sensor(value, thresholds[entity])

            code = {
                "OK": 0,
                "WARNING": 1,
                "CRITICAL": 2,
            }[state]

            overall_code = max(overall_code, code)

            display_state = payload.get("state", str(value))
            messages.append(
                f"[{state}] {entity}: {display_state}"
            )

            if not args.no_perfdata:
                label = format_perfdata_label(entity)
                warning_perf = warning or ""
                critical_perf = critical or ""

                perfdata.append(
                    f"'{label}'={value};{warning_perf};{critical_perf};;"
                )

        except RuntimeError as exc:
            overall_code = max(overall_code, 3)
            messages.append(f"[UNKNOWN] {entity}: {exc}")

    state_name = {
        0: "OK",
        1: "WARNING",
        2: "CRITICAL",
        3: "UNKNOWN",
    }[overall_code]

    print(f"[{state_name}] {args.title}")
    for message in messages:
        print(f"\\_ {message}")

    if perfdata:
        print("| " + " ".join(perfdata))

    return overall_code


if __name__ == "__main__":
    raise SystemExit(main())