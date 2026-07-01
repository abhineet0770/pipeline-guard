# GridWatch

Passive OT Monitoring and Process-Aware Risk Assessment using GRFICSv3

GridWatch is a research-oriented Operational Technology (OT) cybersecurity project focused on studying and implementing the core concepts behind modern industrial monitoring platforms.

The project uses the GRFICSv3 industrial control system testbed to simulate a realistic oil pipeline environment, with a two-laptop lab passively mirroring ICS traffic, parsing Modbus TCP, and generating process-aware alerts forwarded to Azure.

## Project Motivation

Industrial environments differ significantly from traditional IT networks because cyber events can directly affect physical processes.

Modern OT security platforms provide visibility into industrial assets, communications, and operational risks. Understanding how these systems function requires knowledge of industrial protocols, network monitoring, process behavior, and engineering-driven risk assessment.

GridWatch was created as a practical research project to explore these concepts in a realistic environment and better understand the workflow behind process-aware industrial monitoring systems. It is not intended to replace commercial OT security products — it's a research, learning, and implementation exercise.

## Architecture

Two physical laptops connected via crossover Ethernet, isolating the OT lab from the daily-driver network:

```
Laptop A (192.168.10.1)    <──crossover Ethernet──>      Laptop B (192.168.10.2)
                                                                  │
                                                          Ubuntu VM (vboxuser@192.168.29.83)
                                                                  │
                                                          GRFICSv3 (7 Docker containers)
                                                          ├── PLC
                                                          ├── HMI
                                                          ├── Engineering Workstation
                                                          ├── Router
                                                          ├── Process Simulation
                                                          └── 6x Remote IO Modbus servers
                                                              (192.168.95.10–15)
                                                                  │
                                                          ICS Network (192.168.95.0/24)
```

**Traffic mirroring:** `tcpdump` piped over SSH from the Ubuntu VM — fully passive, no active Modbus polling (no PyModbus).

**Modbus register map (GRFICSv3):**
| Register | Meaning |
|---|---|
| IR 108 | Reactor pressure |
| HR 100–103 | PLC output words |
| HR 1024–1028 | Sticky setpoints |

**Alerting:** Process-aware rules (R001–R004) grounded in IEC 62443, NERC CIP, and NIST SP 800-82, forwarding alerts to an Azure Logic App with Blob Storage as the alert store (replacing a traditional historian).

## Project Status

### ✅ Completed
- GitHub repository initialization
- Ubuntu VM deployment, Docker install/validation
- GRFICSv3 deployment — all 7 containers healthy
- Crossover Ethernet setup between ASUS (witcher) and Dell (beast)
- Full SSH jump chain verified to Ubuntu VM
- Live Modbus TCP traffic confirmed via `tcpdump` on the ICS network
- GRFICSv3 Modbus register map identified
- Alert rule design (R001–R004) mapped to IEC 62443 / NERC CIP / NIST SP 800-82

### 🔄 In Progress
- Reading *Practical Industrial Cybersecurity* (Brooks & Craig) for process-monitoring grounding
- Writing `gridwatch.py` (pyshark/tshark-based passive parser, running on the Ubuntu VM)

### ⏳ Planned
- Process-state tracking module
- Risk assessment / alert generation engine (R001–R004 implementation)
- Azure Logic App + Blob Storage integration
- Testing and validation
- Final documentation

## Development Roadmap

| Phase | Status |
|---|---|
| Environment Setup & Deployment | ✅ Completed |
| Network & SSH Chain Verification | ✅ Completed |
| Traffic Mirroring (tcpdump over SSH) | ✅ Completed |
| Register Map & Alert Rule Design | ✅ Completed |
| `gridwatch.py` (pyshark/tshark parser) | 🔄 In Progress |
| Process-State Tracking | ⏳ Planned |
| Risk Assessment / Alert Engine | ⏳ Planned |
| Azure Integration | ⏳ Planned |
| Testing & Validation | ⏳ Planned |
| Final Documentation | ⏳ Planned |

## Current Environment

| Category | Technology |
|---|---|
| Virtualization | Oracle VirtualBox |
| Operating System | Ubuntu Linux (VM), Windows 11 (host laptops) |
| Containerization | Docker |
| OT Testbed | GRFICSv3 |
| Lab Network | Crossover Ethernet, 192.168.10.0/24 |
| ICS Network | 192.168.95.0/24 |
| Traffic Capture | tcpdump over SSH → pyshark/tshark |
| Alert Forwarding | Azure Logic App |
| Alert Storage | Azure Blob Storage |

## Repository Structure

```
gridwatch/
│
├── README.md
├── docs/
├── reports/
├── screenshots/
├── diagram/
├── notes/
└── src/
```

## Learning Goals

- Operational Technology (OT) Security
- Industrial Control Systems (ICS)
- Industrial Network Monitoring
- Process-Aware Security Concepts
- Risk Assessment Methodologies (IEC 62443 / NERC CIP / NIST SP 800-82)
- Industrial Cybersecurity Research
- Dockerized OT Environments
- Cloud Integration for OT Alerting (Azure)

## Author

**Abhineet Tandon**
B.Tech Computer Science and Engineering (Cybersecurity), UPES Dehradun
OT Security Intern, OilSERV

Research Interests: OT Security · Industrial Cybersecurity · Network Monitoring · Process-Aware Detection

## Acknowledgments

This project uses [GRFICSv3](https://github.com/Fortiphyd/GRFICSv3), an open-source
OT/ICS security lab developed by Fortiphyd Logic (originally with Georgia Tech).
GRFICS is not affiliated with or endorsing this project.

Citation: Formby, D., Rad, M., and Beyah, R. "Lowering the Barriers to Industrial
Control System Security with GRFICS." USENIX Workshop on Advances in Security
Education (ASE 18).
