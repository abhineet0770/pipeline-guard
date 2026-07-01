"""
Blocking demo script for GridWatch.

This replays a short sequence of synthetic Modbus events with delays so you can
watch packet output and alert generation in real time without needing live OT
traffic or packet capture privileges.
"""

import time
from collections.abc import Callable
from datetime import datetime

from gridwatch import config
from gridwatch.alert_rules import check_rules
from gridwatch.gridwatch import print_alert, print_parsed_packet


def make_packet(
    *,
    src_ip: str,
    dst_ip: str,
    func_code: int,
    direction: str,
    trans_id: int,
    registers: dict[int, int] | None = None,
    ref_num: int | None = None,
    values: list[int] | None = None,
    timestamp: datetime | None = None,
) -> dict:
    return {
        "timestamp": timestamp or datetime.now(),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "trans_id": trans_id,
        "direction": direction,
        "func_code": func_code,
        "ref_num": ref_num,
        "registers": registers or {},
        "values": values or [],
    }


def replay_event(state: dict, packet_factory: Callable[[], dict], delay_seconds: float = 1.5) -> None:
    packet = packet_factory()
    print_parsed_packet(packet)
    alerts = check_rules(state, packet)
    for alert in alerts:
        print_alert(alert)
    time.sleep(delay_seconds)


def main() -> None:
    state = {"reactor_pressure": None, "valve_closed": None}

    print("Starting GridWatch blocking demo...")
    print("This will replay synthetic Modbus traffic and print alerts live.\n")
    time.sleep(1.0)

    events = [
        lambda: make_packet(
            src_ip=config.PLC_IP,
            dst_ip=config.EWS_IP,
            func_code=4,
            direction="response",
            trans_id=1,
            registers={config.REG_REACTOR_PRESSURE: 3000},
        ),
        lambda: make_packet(
            src_ip=config.EWS_IP,
            dst_ip=config.PLC_IP,
            func_code=config.FC_WRITE_SINGLE,
            direction="request",
            trans_id=2,
            registers={config.REG_VALVE_STATE: config.VALVE_CLOSED_VALUE},
        ),
        lambda: make_packet(
            src_ip="192.168.90.25",
            dst_ip=config.PLC_IP,
            func_code=config.FC_WRITE_MULTIPLE,
            direction="request",
            trans_id=3,
        ),
        lambda: make_packet(
            src_ip=config.EWS_IP,
            dst_ip=config.PLC_IP,
            func_code=config.FC_WRITE_SINGLE,
            direction="request",
            trans_id=4,
            timestamp=datetime(2026, 6, 30, 22, 15, 0),
        ),
        lambda: make_packet(
            src_ip="192.168.95.55",
            dst_ip=config.PLC_IP,
            func_code=4,
            direction="request",
            trans_id=5,
        ),
    ]

    for packet_factory in events:
        replay_event(state, packet_factory)

    print("\nDemo complete.")


if __name__ == "__main__":
    main()
