"""
Alert detection engine for GridWatch.
Implements the stateful and packet-level inspection rules (R001–R004)
to identify anomalous process states and suspicious Modbus TCP network actions.
"""

import ipaddress
from datetime import datetime, time
try:
    from gridwatch import config
except ImportError:
    import config


def build_alert(
    rule_id: str,
    severity: str,
    description: str,
    parsed_packet: dict,
) -> dict:
    return {
        "rule_id": rule_id,
        "severity": severity,
        "description": description,
        "timestamp": parsed_packet["timestamp"],
        "src_ip": parsed_packet["src_ip"],
        "dst_ip": parsed_packet["dst_ip"],
    }

def is_outside_maintenance_window(dt: datetime) -> bool:
    """
    Check if the given datetime is outside the configured maintenance window.
    
    Args:
        dt (datetime): Timestamp of the event.
        
    Returns:
        bool: True if outside the maintenance window, False otherwise.
    """
    try:
        start_h, start_m = map(int, config.MAINTENANCE_START.split(':'))
        end_h, end_m = map(int, config.MAINTENANCE_END.split(':'))
    except (ValueError, AttributeError, TypeError):
        start_h, start_m = 9, 0
        end_h, end_m = 17, 0

    evt_time = dt.time()
    start_time = time(start_h, start_m)
    end_time = time(end_h, end_m)

    if start_time <= end_time:
        return not (start_time <= evt_time <= end_time)
    else:
        # Handles overnight maintenance windows (e.g. 22:00 to 06:00)
        return not (evt_time >= start_time or evt_time <= end_time)

def check_r001_reactor_pressure(state: dict, parsed_packet: dict) -> dict:
    """
    R001: Reactor pressure > 2900 kPa AND valve closed simultaneously = CRITICAL
    
    Checks if the process state transitions into a hazardous state.
    
    Args:
        state (dict): Running state of monitored Modbus registers.
        parsed_packet (dict): The parsed packet data.
        
    Returns:
        dict or None: Alert payload if triggered, otherwise None.
    """
    pressure = state.get('reactor_pressure')
    valve_closed = state.get('valve_closed')

    if pressure is not None and valve_closed is not None:
        if pressure > config.REACTOR_PRESSURE_MAX_KPA and valve_closed:
            return build_alert(
                "R001",
                "CRITICAL",
                (
                    "Process Danger: Reactor pressure exceeds threshold "
                    f"({pressure} kPa > {config.REACTOR_PRESSURE_MAX_KPA} kPa) "
                    "while outlet valve is closed."
                ),
                parsed_packet,
            )
    return None

def check_r002_dmz_write(parsed_packet: dict) -> dict:
    """
    R002: FC06/FC16 write originating from DMZ network (192.168.90.x) to PLC = CRITICAL
    
    Args:
        parsed_packet (dict): The parsed packet data.
        
    Returns:
        dict or None: Alert payload if triggered, otherwise None.
    """
    src_ip = parsed_packet["src_ip"]
    dst_ip = parsed_packet["dst_ip"]
    func_code = parsed_packet["func_code"]
    direction = parsed_packet.get("direction")

    # Only inspect requests targeting the PLC
    if direction == "request" and dst_ip == config.PLC_IP:
        if func_code in config.SUSPICIOUS_FUNCTION_CODES:
            try:
                src_addr = ipaddress.ip_address(src_ip)
                if src_addr in config.DMZ_SUBNET:
                    return build_alert(
                        "R002",
                        "CRITICAL",
                        (
                            "Security Violation: Suspicious Modbus write "
                            f"(FC {func_code}) originating from DMZ IP ({src_ip}) "
                            f"directed to PLC ({dst_ip})."
                        ),
                        parsed_packet,
                    )
            except ValueError:
                pass
    return None

def check_r003_ews_write_out_of_hours(parsed_packet: dict) -> dict:
    """
    R003: Engineering Workstation (EWS) writes to PLC outside a defined maintenance window = HIGH
    
    Args:
        parsed_packet (dict): The parsed packet data.
        
    Returns:
        dict or None: Alert payload if triggered, otherwise None.
    """
    src_ip = parsed_packet["src_ip"]
    dst_ip = parsed_packet["dst_ip"]
    func_code = parsed_packet["func_code"]
    direction = parsed_packet.get("direction")
    timestamp = parsed_packet["timestamp"]

    # Check if a write query comes from the EWS targeting the PLC
    if direction == "request" and src_ip == config.EWS_IP and dst_ip == config.PLC_IP:
        if func_code in config.SUSPICIOUS_FUNCTION_CODES:
            if is_outside_maintenance_window(timestamp):
                return build_alert(
                    "R003",
                    "HIGH",
                    (
                        "Policy Deviation: EWS write command to PLC observed "
                        "outside maintenance window "
                        f"({config.MAINTENANCE_START}-{config.MAINTENANCE_END})."
                    ),
                    parsed_packet,
                )
    return None

def check_r004_unknown_ip(parsed_packet: dict) -> dict:
    """
    R004: Unknown/unrecognized IP address appears on the ICS network (192.168.95.0/24) = HIGH
    
    Args:
        parsed_packet (dict): The parsed packet data.
        
    Returns:
        dict or None: Alert payload if triggered, otherwise None.
    """
    for ip in (parsed_packet["src_ip"], parsed_packet["dst_ip"]):
        try:
            addr = ipaddress.ip_address(ip)
            # Only trigger if the IP belongs to the local ICS network but isn't whitelisted
            if addr in config.ICS_SUBNET and ip not in config.KNOWN_GOOD_IPS:
                return build_alert(
                    "R004",
                    "HIGH",
                    (
                        "Asset Discovery Alert: Unrecognized/unauthorized IP "
                        f"address ({ip}) detected on local ICS network."
                    ),
                    parsed_packet,
                )
        except ValueError:
            pass
    return None

def check_rules(state: dict, parsed_packet: dict) -> list:
    """
    Process an incoming parsed packet, update register states, and verify all alert rules.
    
    Args:
        state (dict): Shared state representing the running process registers.
        parsed_packet (dict): The parsed packet metadata.
        
    Returns:
        list: A list of triggered alert dictionaries.
    """
    # 1. Update the process state with any registers contained in this packet
    packet_regs = parsed_packet.get("registers", {})
    if config.REG_REACTOR_PRESSURE in packet_regs:
        state["reactor_pressure"] = packet_regs[config.REG_REACTOR_PRESSURE]
    
    if config.REG_VALVE_STATE in packet_regs:
        state["valve_closed"] = (packet_regs[config.REG_VALVE_STATE] == config.VALVE_CLOSED_VALUE)

    # 2. Check rules and accumulate alerts
    alerts = []
    rule_results = (
        check_r001_reactor_pressure(state, parsed_packet),
        check_r002_dmz_write(parsed_packet),
        check_r003_ews_write_out_of_hours(parsed_packet),
        check_r004_unknown_ip(parsed_packet),
    )

    for alert in rule_results:
        if alert:
            alerts.append(alert)

    return alerts
