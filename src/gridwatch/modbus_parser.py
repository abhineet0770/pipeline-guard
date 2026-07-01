"""
Modbus TCP packet parser module.

Uses pyshark to perform passive capture and parse fields from Modbus TCP packets.
Tracks and correlates Modbus transactions to map read response values back to the
register addresses requested earlier in the exchange.
"""

import asyncio
import logging
from collections.abc import Callable
from datetime import datetime

import pyshark

try:
    from gridwatch import config
except ImportError:
    import config


logger = logging.getLogger(__name__)


class ModbusParser:
    def __init__(self, interface: str):
        """
        Initialize the parser with the target network interface.

        Args:
            interface (str): Name of the network interface to capture on.
        """
        self.interface = interface
        self.transaction_map: dict[int, dict[str, int | str | None]] = {}

    @staticmethod
    def _extract_register_values(packet) -> list[int]:
        """Return decoded register values from the Modbus layer when present."""
        if not hasattr(packet.modbus, "regval_uint16"):
            return []

        try:
            fields = packet.modbus.regval_uint16.all_fields
        except AttributeError:
            fields = [packet.modbus.regval_uint16]

        values: list[int] = []
        for field in fields:
            for candidate in (getattr(field, "raw_value", None), getattr(field, "show", None)):
                if candidate is None:
                    continue
                try:
                    values.append(int(candidate, 16))
                    break
                except (ValueError, TypeError):
                    try:
                        values.append(int(candidate))
                        break
                    except (ValueError, TypeError):
                        continue
        return values

    def parse_packet(self, packet) -> dict | None:
        """
        Extract Modbus TCP fields from a captured packet.

        Correlates read responses with read requests to map register numbers to
        their values.
        """
        if "mbtcp" not in packet or "modbus" not in packet:
            return None

        if not hasattr(packet, "ip"):
            return None

        src_ip = packet.ip.src
        dst_ip = packet.ip.dst

        try:
            trans_id = int(packet.mbtcp.trans_id)
            func_code = int(packet.modbus.func_code)
        except (AttributeError, ValueError):
            return None

        direction = "unknown"
        if hasattr(packet, "tcp"):
            if packet.tcp.dstport == str(config.MODBUS_PORT):
                direction = "request"
            elif packet.tcp.srcport == str(config.MODBUS_PORT):
                direction = "response"

        ref_num = None
        registers: dict[int, int] = {}
        values = self._extract_register_values(packet)

        if direction == "request":
            if hasattr(packet.modbus, "reference_num"):
                try:
                    ref_num = int(packet.modbus.reference_num)
                except ValueError:
                    pass

            if func_code in (3, 4):
                try:
                    word_cnt = int(packet.modbus.word_cnt)
                except (AttributeError, ValueError):
                    word_cnt = 1
                self.transaction_map[trans_id] = {
                    "func_code": func_code,
                    "ref_num": ref_num,
                    "word_cnt": word_cnt,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                }
            elif func_code in (6, 16) and ref_num is not None and values:
                for index, value in enumerate(values):
                    registers[ref_num + index] = value

        elif direction == "response":
            request_info = self.transaction_map.pop(trans_id, None)
            if request_info:
                ref_num = request_info.get("ref_num")
                if ref_num is not None and values:
                    for index, value in enumerate(values):
                        registers[ref_num + index] = value

        sniff_time = getattr(packet, "sniff_time", None) or datetime.now()

        return {
            "timestamp": sniff_time,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "trans_id": trans_id,
            "direction": direction,
            "func_code": func_code,
            "ref_num": ref_num,
            "registers": registers,
            "values": values,
        }

    def start_capture(self, callback: Callable[[dict], None]) -> None:
        """
        Begin capturing Modbus traffic on the configured interface.

        Invokes `callback` with parsed packet metadata when a Modbus packet is detected.
        """
        try:
            asyncio.get_event_loop()
        except RuntimeError:
            asyncio.set_event_loop(asyncio.new_event_loop())

        capture = pyshark.LiveCapture(
            interface=self.interface,
            bpf_filter=f"tcp port {config.MODBUS_PORT}",
        )

        for packet in capture.sniff_continuously():
            try:
                parsed = self.parse_packet(packet)
                if parsed:
                    callback(parsed)
            except Exception:
                logger.exception("Failed to parse captured packet; continuing capture loop.")
