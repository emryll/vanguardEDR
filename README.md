## What is it?
Vanguard EDR is a Endpoint Detection & Response system for Windows, which aims to detect malicious behavior on multiple endpoints, send alerts about it to a central UI and attempt to automatically stop malicious behavior from happening.
It consists of 5 main components:
- Agent; the brain of each endpoint--detects malicious behavior and handles things such as memory scans
- Telemetry DLL; injected into each tracked process, gathers telemetry data and sends it to agent
- Kernel driver; protects the system from tampering and handles kernel callbacks to get informed on events like process creation
- Central server; gathers all endpoints' data for a centralized view and provides it to the UI, also forwards commands to agents
- UI; provides the operator a clear centralized view of alerts, telemetry data, and control over each endpoint

It is still in very early development and not yet ready for use. I aim to get the core (agent, telemetry DLL and kernel driver) working by end of summer 2025, and full beta working by end of 2025.
