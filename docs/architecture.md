# Pipeline Guard Architecture

## Overview

Pipeline Guard is a passive OT monitoring platform designed to observe industrial communications within the GRFICSv3 environment and provide process-aware risk assessment.

The system does not directly interact with industrial devices and operates as a monitoring-only solution.

---

## High-Level Architecture

Laptop A

* Windows 11
* Ubuntu VM
* GRFICSv3 Environment

Contains:

* PLC
* HMI
* Engineering Workstation
* Router
* Industrial Process Simulation

Laptop B

* Ubuntu
* Pipeline Guard

Responsibilities:

* Passive traffic capture
* Asset discovery
* Process-state tracking
* Risk assessment
* Alert generation

Azure

Responsibilities:

* Alert storage
* Historical logs
* Analytics

---

## Data Flow

GRFICSv3

↓

Mirrored Traffic

↓

Pipeline Guard

↓

Analysis Engine

↓

Alert Generation

↓

Azure Storage

---

## Planned Modules

### Asset Discovery Module

Purpose:

Identify industrial assets through passive network observation.

Expected Outputs:

* Device IP address
* Device role
* Protocol usage

---

### Process-State Tracking Module

Purpose:

Maintain awareness of process conditions.

Tracked Variables:

* Pressure
* Valve state
* Pump state

---

### Risk Assessment Engine

Purpose:

Evaluate observed actions against engineering rules.

Example Rule:

IF

Pressure > Threshold

AND

Valve Close Command Detected

THEN

Generate Pressure Surge Risk Alert

---

## Security Principles

* Passive monitoring only
* No modification of industrial devices
* No control commands transmitted
* Read-only visibility
* Out-of-band alerting
