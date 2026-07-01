import unittest
from datetime import datetime
from types import SimpleNamespace

from gridwatch import alert_rules, config
from gridwatch.modbus_parser import ModbusParser


def make_parsed_packet(
    *,
    src_ip: str,
    dst_ip: str,
    func_code: int,
    direction: str = "request",
    registers: dict[int, int] | None = None,
    timestamp: datetime | None = None,
    trans_id: int = 1,
    ref_num: int | None = None,
    values: list[int] | None = None,
) -> dict:
    return {
        "timestamp": timestamp or datetime(2026, 6, 30, 20, 0, 0),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "trans_id": trans_id,
        "direction": direction,
        "func_code": func_code,
        "ref_num": ref_num,
        "registers": registers or {},
        "values": values or [],
    }


class FakeField:
    def __init__(self, raw_value=None, show=None):
        self.raw_value = raw_value
        self.show = show


class FakeRegisterValue:
    def __init__(self, fields):
        self.all_fields = fields


class FakePacket:
    def __init__(
        self,
        *,
        src_ip: str,
        dst_ip: str,
        trans_id: int,
        func_code: int,
        dstport: str | None = None,
        srcport: str | None = None,
        reference_num: int | None = None,
        word_cnt: int | None = None,
        reg_fields: list[FakeField] | None = None,
        sniff_time: datetime | None = None,
    ):
        self.ip = SimpleNamespace(src=src_ip, dst=dst_ip)
        self.mbtcp = SimpleNamespace(trans_id=str(trans_id))
        self.modbus = SimpleNamespace(func_code=str(func_code))
        self.tcp = SimpleNamespace(
            dstport=dstport if dstport is not None else "",
            srcport=srcport if srcport is not None else "",
        )
        self.sniff_time = sniff_time or datetime(2026, 6, 30, 12, 0, 0)

        if reference_num is not None:
            self.modbus.reference_num = str(reference_num)
        if word_cnt is not None:
            self.modbus.word_cnt = str(word_cnt)
        if reg_fields is not None:
            self.modbus.regval_uint16 = FakeRegisterValue(reg_fields)

    def __contains__(self, item):
        return item in {"mbtcp", "modbus"}


class AlertRuleTests(unittest.TestCase):
    def test_r001_triggers_when_pressure_high_and_valve_closed(self):
        state = {"reactor_pressure": None, "valve_closed": None}

        pressure_packet = make_parsed_packet(
            src_ip=config.PLC_IP,
            dst_ip=config.EWS_IP,
            func_code=4,
            direction="response",
            registers={config.REG_REACTOR_PRESSURE: 3000},
        )
        alerts = alert_rules.check_rules(state, pressure_packet)
        self.assertEqual(alerts, [])

        valve_packet = make_parsed_packet(
            src_ip=config.EWS_IP,
            dst_ip=config.PLC_IP,
            func_code=config.FC_WRITE_SINGLE,
            direction="request",
            registers={config.REG_VALVE_STATE: config.VALVE_CLOSED_VALUE},
        )
        alerts = alert_rules.check_rules(state, valve_packet)

        rule_ids = {alert["rule_id"] for alert in alerts}
        self.assertIn("R001", rule_ids)

    def test_r002_triggers_for_dmz_write_to_plc(self):
        packet = make_parsed_packet(
            src_ip="192.168.90.25",
            dst_ip=config.PLC_IP,
            func_code=config.FC_WRITE_SINGLE,
            direction="request",
        )

        alert = alert_rules.check_r002_dmz_write(packet)
        self.assertIsNotNone(alert)
        self.assertEqual(alert["rule_id"], "R002")

    def test_r003_triggers_for_ews_write_outside_maintenance(self):
        packet = make_parsed_packet(
            src_ip=config.EWS_IP,
            dst_ip=config.PLC_IP,
            func_code=config.FC_WRITE_MULTIPLE,
            direction="request",
            timestamp=datetime(2026, 6, 30, 22, 15, 0),
        )

        alert = alert_rules.check_r003_ews_write_out_of_hours(packet)
        self.assertIsNotNone(alert)
        self.assertEqual(alert["rule_id"], "R003")

    def test_r004_triggers_for_unknown_ics_ip(self):
        packet = make_parsed_packet(
            src_ip="192.168.95.55",
            dst_ip=config.PLC_IP,
            func_code=4,
            direction="request",
        )

        alert = alert_rules.check_r004_unknown_ip(packet)
        self.assertIsNotNone(alert)
        self.assertEqual(alert["rule_id"], "R004")

    def test_maintenance_window_handles_overnight_ranges(self):
        original_start = config.MAINTENANCE_START
        original_end = config.MAINTENANCE_END
        try:
            config.MAINTENANCE_START = "22:00"
            config.MAINTENANCE_END = "06:00"

            self.assertFalse(
                alert_rules.is_outside_maintenance_window(datetime(2026, 6, 30, 23, 0, 0))
            )
            self.assertTrue(
                alert_rules.is_outside_maintenance_window(datetime(2026, 6, 30, 12, 0, 0))
            )
        finally:
            config.MAINTENANCE_START = original_start
            config.MAINTENANCE_END = original_end


class ModbusParserTests(unittest.TestCase):
    def test_parse_request_and_response_maps_read_registers(self):
        parser = ModbusParser(interface="dummy0")

        request_packet = FakePacket(
            src_ip=config.EWS_IP,
            dst_ip=config.PLC_IP,
            trans_id=101,
            func_code=4,
            dstport=str(config.MODBUS_PORT),
            reference_num=config.REG_REACTOR_PRESSURE,
            word_cnt=1,
        )
        parsed_request = parser.parse_packet(request_packet)

        self.assertIsNotNone(parsed_request)
        self.assertEqual(parsed_request["direction"], "request")
        self.assertEqual(parsed_request["ref_num"], config.REG_REACTOR_PRESSURE)

        response_packet = FakePacket(
            src_ip=config.PLC_IP,
            dst_ip=config.EWS_IP,
            trans_id=101,
            func_code=4,
            srcport=str(config.MODBUS_PORT),
            reg_fields=[FakeField(raw_value="0bb8")],
        )
        parsed_response = parser.parse_packet(response_packet)

        self.assertIsNotNone(parsed_response)
        self.assertEqual(parsed_response["direction"], "response")
        self.assertEqual(parsed_response["registers"], {config.REG_REACTOR_PRESSURE: 3000})

    def test_parse_write_request_extracts_written_registers(self):
        parser = ModbusParser(interface="dummy0")

        write_packet = FakePacket(
            src_ip=config.EWS_IP,
            dst_ip=config.PLC_IP,
            trans_id=102,
            func_code=config.FC_WRITE_SINGLE,
            dstport=str(config.MODBUS_PORT),
            reference_num=config.REG_VALVE_STATE,
            reg_fields=[FakeField(raw_value="0000")],
        )
        parsed = parser.parse_packet(write_packet)

        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["registers"], {config.REG_VALVE_STATE: 0})


if __name__ == "__main__":
    unittest.main()
