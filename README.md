
# umink

![License](https://img.shields.io/github/license/link-mink/micro-mink)
![Last Commit](https://img.shields.io/github/last-commit/link-mink/micro-mink)
![Stars](https://img.shields.io/github/stars/link-mink/micro-mink?style=social)
[![CI](https://github.com/link-mink/micro-mink/actions/workflows/on_push.yml/badge.svg)](https://github.com/link-mink/micro-mink/actions/workflows/on_push.yml)
[![codecov](https://codecov.io/gh/link-mink/micro-mink/branch/main/graph/badge.svg)](https://codecov.io/gh/link-mink/micro-mink)
![Lua](https://img.shields.io/badge/lua-5.3%2B-blue)

**umink** (micro-mink) is a lightweight, distributed software framework designed for **low-power devices**, **IoT environments**, and **industrial systems**.  
It hides complex operations behind the simplicity of **Lua scripting**, enabling developers and operators to build powerful distributed systems without a steep learning curve.

> ⚡ **Proven in production**: umink is actively deployed on **cable modem CPE devices** across **three telecom operators**, demonstrating its reliability and efficiency in real-world telecom environments.



## Key Features

- **Lightweight and small footprint**  
  Runs efficiently on constrained devices such as embedded Linux, IoT gateways, or industrial controllers.

- **Lua-first simplicity**  
  All handlers for **data acquisition, transmission, and actions** are written in Lua, making customization simple and approachable.

- **Distributed system with federated data sharing**  
  umink nodes can share data with each other across a federated network.

- **Two supported protocols**  
  - [CoAP](https://libcoap.net/) for constrained, lightweight deployments.  
  - [MQTT](https://mqtt.org/) (via [Eclipse Mosquitto](https://mosquitto.org/)) for integration with external tools (analytics, web frontends, dashboards).

- **AI-powered anomaly detection**  
  - Built-in AI plugin for detecting anomalies in streaming data.  
  - Supports federated data sharing → enabling collaborative dataset building across nodes.  
  - Collected data can later be used for **training neural networks** for more accurate anomaly detection.

- **MCP (Model Control Protocol) integration**  
  - Connect umink to external **AI agents**.  
  - Agents can:  
    - Inspect and analyze real-time data.  
    - Call Lua handlers directly.  
    - Update or replace Lua scripts on the fly.  
  - Enables creation of **fully automated, unmanned systems**.

- **Domain agnostic**  
  - Designed for IoT, industrial monitoring, predictive maintenance, smart infrastructure, and beyond.  
  - No hard limits on how it can be applied.



## Architecture Overview

    ┌─────────────┐
    │   Sensors   │
    └──────┬──────┘
           │
    ┌──────▼──────┐
    │   Lua I/O   │   <-- Handlers for acquisition & actions
    └──────┬──────┘
           │
    ┌──────▼──────┐
    │   umink     │
    └──────┬──────┘
     CoAP / MQTT
           │
    ┌──────▼─────────┐
    │ Federated Mesh │
    └──────┬─────────┘
           │
    ┌──────▼────────────────┐
    │ External Tools / AI   │
    │ (Analytics, Frontend) │
    └───────────────────────┘

## Getting Started

### Prerequisites
- Linux system (embedded or server-grade)  
- [Lua 5.3+](https://www.lua.org/)  
- [Mosquitto MQTT broker](https://mosquitto.org/) (if using MQTT)  
- [ONNX Runtime](https://onnxruntime.ai/) (for AI plugin support)

### AI & MCP Integration
-  **Anomaly detection plugin**  
  Load pre-trained ONNX models for local anomaly detection.

- **MCP bridge**  
  Allows coupling with AI agents (e.g. OpenAI, LangChain, custom LLM-based controllers).

  Agents can:
    - Query live data
    - Call Lua handlers.
    - Rewrite/update handlers dynamically

  This creates a **self-adaptive** system where AI can manage, tune, and evolve deployments without human intervention.


### Use Cases

- Predictive maintenance in industrial plants
- IoT data collection across distributed nodes
- Smart city infrastructure monitoring
- Federated edge learning for anomaly detection
- Low-power device orchestration with AI oversight
- Device monitoring and automation


# License

This software is licensed under the [MIT license](https://opensource.org/licenses/MIT)
