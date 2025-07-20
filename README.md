## What is it?
Vanguard EDR is a Endpoint Detection & Response system for Windows, which aims to detect malicious behavior on multiple endpoints, send alerts about it to a central UI and attempt to automatically stop malicious behavior from happening.
It consists of 5 main components:
- Agent; the brain of each endpoint--detects malicious behavior and handles things such as memory scans
- Telemetry DLL; injected into each tracked process, gathers telemetry data and sends it to agent
- Kernel driver; protects the system from tampering and handles kernel callbacks to get informed on events like process creation
- Central server; gathers all endpoints' data for a centralized view and provides it to the UI, also forwards commands to agents
- UI; provides the operator a clear centralized view of alerts, telemetry data, and control over each endpoint

For the beta version detection comes from the following scans:
- Static analysis of files when they are created, modified, or opened(loaded)
- Memory scanning with YARA. Different areas of memory scanned based on context; both periodic scans and event triggered scans
- Behavior patterns from API calls, filesystem operations and registry modification
- Basic thread scanning
- Network behavior

There are also multiple anti-tampering tactics in place:
- Heartbeat mechanism to insure hook DLL stays in place, to gather telemetry
- Periodic hash comparisons to detect removal of hooks and other kinds of patching 
- Self-integrity checks

I'm planning to add some additional scans in the future but these form the core for detections.
These scans depend on a few types of rules: YARA rules for static and memory scans, API behavior patterns, filesystem behavior patterns and registry behavior patterns. You can use the default rules or add your own by adding files to rules/.

This project is still in very early development and not yet ready for use. I aim to get the core (agent, telemetry DLL and kernel driver) working by end of summer 2025, and full beta working by end of 2025.
So far what is ready:
- Static analysis engine (integrated + standalone tool)
- Memory scanning functionality (utilizing YARA-X)
- Pattern detection logic and internal telemetry history cleanup mechanism
- Most of hook DLL
- IAT hook detection
