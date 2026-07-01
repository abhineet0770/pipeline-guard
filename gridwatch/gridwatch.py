"""
GridWatch CLI main entry point.
Uses typer for CLI definition. For Phase 4, it initializes the ModbusParser,
maintains register states, checks alert rules, and logs security alerts and traffic details
to a local log file in JSON lines format.
"""

import json
import logging
import os
from typing import Any

import typer

try:
    from gridwatch import config
    from gridwatch.modbus_parser import ModbusParser
    from gridwatch.alert_rules import check_rules
except ImportError:
    import config
    from modbus_parser import ModbusParser
    from alert_rules import check_rules

PacketData = dict[str, Any]

app = typer.Typer(help="GridWatch: Passive OT Network Security Monitoring Tool")

def setup_logging() -> logging.Logger:
    """
    Ensure the log directory exists and configure the JSON lines log file handler.
    """
    os.makedirs(config.LOG_DIR, exist_ok=True)
    
    logger = logging.getLogger("gridwatch")
    logger.setLevel(logging.INFO)
    
    # Avoid duplicate handlers if setup_logging is called multiple times
    if logger.hasHandlers():
        logger.handlers.clear()
        
    file_handler = logging.FileHandler(config.LOG_FILE_PATH, encoding='utf-8')
    file_handler.setLevel(logging.INFO)
    
    # Format log entries as plain messages (JSON serializations)
    formatter = logging.Formatter('%(message)s')
    file_handler.setFormatter(formatter)
    
    logger.addHandler(file_handler)
    return logger

def print_parsed_packet(parsed_packet: PacketData) -> None:
    """
    Format and display parsed Modbus TCP packet details to console.
    """
    ts = parsed_packet["timestamp"].strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    direction_arrow = "-->" if parsed_packet["direction"] == "request" else "<--"
    
    header = f'[{ts}] {parsed_packet["src_ip"]} {direction_arrow} {parsed_packet["dst_ip"]}'
    meta = f'FC: {parsed_packet["func_code"]:02d} | TransID: {parsed_packet["trans_id"]}'
    
    typer.echo(f"{typer.style(header, fg=typer.colors.GREEN)} | {typer.style(meta, fg=typer.colors.CYAN)}")
    
    if parsed_packet["registers"]:
        reg_details = ", ".join(
            f"Reg {register}: {value}" for register, value in parsed_packet["registers"].items()
        )
        typer.echo(f"  {typer.style('Mapped Registers:', fg=typer.colors.YELLOW)} {reg_details}")
    elif parsed_packet["values"]:
        val_details = ", ".join(map(str, parsed_packet["values"]))
        typer.echo(f"  {typer.style('Raw Values:', fg=typer.colors.MAGENTA)} [{val_details}]")
    elif parsed_packet["direction"] == "request" and parsed_packet["ref_num"] is not None:
        typer.echo(
            f"  {typer.style('Read Request starting from:', fg=typer.colors.WHITE)} "
            f'Reg {parsed_packet["ref_num"]}'
        )

def print_alert(alert: PacketData) -> None:
    """
    Display a triggered security alert to the console with color-coded severity.
    """
    ts = alert["timestamp"].strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    severity_str = f'[{alert["severity"]}]'
    rule_info = f'Rule: {alert["rule_id"]}'
    
    if alert["severity"] == "CRITICAL":
        prefix = typer.style(f"!!! {severity_str} {rule_info} !!!", fg=typer.colors.WHITE, bg=typer.colors.RED, bold=True)
        desc = typer.style(alert["description"], fg=typer.colors.RED, bold=True)
    else:  # HIGH
        prefix = typer.style(f"[!] {severity_str} {rule_info} [!]", fg=typer.colors.BLACK, bg=typer.colors.YELLOW, bold=True)
        desc = typer.style(alert["description"], fg=typer.colors.YELLOW, bold=True)
        
    typer.echo(f"{prefix} {typer.style(f'@{ts}', fg=typer.colors.CYAN)}")
    typer.echo(f"  {desc}")


def build_traffic_log_entry(parsed_packet: PacketData) -> PacketData:
    return {
        "timestamp": parsed_packet["timestamp"].isoformat(),
        "event": "traffic",
        "src_ip": parsed_packet["src_ip"],
        "dst_ip": parsed_packet["dst_ip"],
        "direction": parsed_packet["direction"],
        "func_code": parsed_packet["func_code"],
        "trans_id": parsed_packet["trans_id"],
        "registers": {
            str(register): value for register, value in parsed_packet["registers"].items()
        },
    }


def build_alert_log_entry(alert: PacketData) -> PacketData:
    return {
        "timestamp": alert["timestamp"].isoformat(),
        "event": "alert",
        "rule_id": alert["rule_id"],
        "severity": alert["severity"],
        "description": alert["description"],
        "src_ip": alert["src_ip"],
        "dst_ip": alert["dst_ip"],
    }

@app.command()
def monitor(
    interface: str = typer.Option(
        ...,
        "--interface",
        "-i",
        help="Network interface to sniff packets on (e.g. eth0, wlan0)"
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Enable verbose output (logs all normal Modbus traffic as well)"
    )
) -> None:
    """
    Start passive Modbus TCP packet capture and analysis.
    """
    typer.secho(f"[*] Initializing GridWatch Passive Monitor...", fg=typer.colors.CYAN, bold=True)
    typer.echo(f"[*] Subnet Config: ICS={config.ICS_SUBNET_STR}, DMZ={config.DMZ_SUBNET_STR}")
    typer.echo(f"[*] Monitoring interface: {interface}")
    typer.echo(f"[*] Verbose logging: {'ENABLED' if verbose else 'DISABLED'}")
    typer.secho(f"[+] Sniffing Modbus TCP traffic (Port 502)... Press Ctrl+C to stop.", fg=typer.colors.GREEN, bold=True)
    
    # Setup logger
    logger = setup_logging()
    
    # Initialize shared state for stateful rules
    state: PacketData = {"reactor_pressure": None, "valve_closed": None}
    
    def packet_callback(parsed_packet: PacketData) -> None:
        # 1. Print raw parsed packet details to stdout
        print_parsed_packet(parsed_packet)
        
        # 2. Log normal traffic summary if verbose flag is set
        if verbose:
            logger.info(json.dumps(build_traffic_log_entry(parsed_packet)))
        
        # 3. Check rules and generate alerts
        alerts = check_rules(state, parsed_packet)
        for alert in alerts:
            print_alert(alert)
            
            # Log alert event to log file (always logged regardless of verbose flag)
            logger.info(json.dumps(build_alert_log_entry(alert)))

    parser = ModbusParser(interface=interface)
    
    try:
        parser.start_capture(callback=packet_callback)
    except KeyboardInterrupt:
        typer.secho("\n[-] Monitor stopped by user.", fg=typer.colors.YELLOW, bold=True)
    except Exception as exc:
        typer.secho(f"\n[!] Error during packet capture: {exc}", fg=typer.colors.RED, bold=True)
        raise typer.Exit(code=1)

if __name__ == "__main__":
    app()
