"""
Configuration settings for the GridWatch passive OT network monitoring tool.
Defines IP ranges, known-good whitelists, Modbus register mappings, thresholds,
and maintenance windows specific to the GRFICSv3 industrial control system environment.
"""

import ipaddress
import os

# Network Configurations
MODBUS_PORT = 502
ICS_SUBNET_STR = "192.168.95.0/24"
DMZ_SUBNET_STR = "192.168.90.0/24"

ICS_SUBNET = ipaddress.ip_network(ICS_SUBNET_STR)
DMZ_SUBNET = ipaddress.ip_network(DMZ_SUBNET_STR)

# Key Host IP Addresses (Default configuration for GRFICSv3)
PLC_IP = "192.168.95.2"
EWS_IP = "192.168.95.10"

# Whitelist of recognized IP addresses on the ICS network (192.168.95.0/24)
# Any IP on b-ics-net not in this set triggers R004.
KNOWN_GOOD_IPS = {
    "192.168.95.1",   # Gateway/Router
    "192.168.95.2",   # PLC (Programmable Logic Controller)
    "192.168.95.10",  # EWS (Engineering Workstation)
    "192.168.95.20",  # HMI (Human Machine Interface)
    "192.168.95.100", # Passive Monitoring Interface (Self)
}

# Modbus Register Map
# Input Registers (IR)
REG_REACTOR_PRESSURE = 108       # IR 108: Reactor Pressure (kPa)

# We assume HR 100 controls or indicates the reactor outlet valve state.
REG_VALVE_STATE = 100
VALVE_CLOSED_VALUE = 0  # 0 indicates valve is closed, non-zero is open

# Modbus Function Codes
FC_WRITE_SINGLE = 6
FC_WRITE_MULTIPLE = 16

SUSPICIOUS_FUNCTION_CODES = {FC_WRITE_SINGLE, FC_WRITE_MULTIPLE}

# Thresholds & Rules Configuration
REACTOR_PRESSURE_MAX_KPA = 2900.0  # R001: Pressure > 2900 kPa

# Maintenance Window (R003: EWS writes to PLC must be within this window)
# Format: "HH:MM" in local VM time
MAINTENANCE_START = "09:00"
MAINTENANCE_END = "17:00"

# Logging configuration
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = os.path.join(BASE_DIR, "logs")
LOG_FILE_PATH = os.path.join(LOG_DIR, "gridwatch.log")

