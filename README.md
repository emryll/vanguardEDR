## What is it?
This is a Endpoint Detection & Response system for Windows, which aims to detect malicious behavior on multiple endpoints, send alerts about it to a central UI and attempt to automatically stop malicious behavior from happening.
The architectural design consists of 6 main components:
- Agent; the brain of each endpoint--detects malicious behavior and handles things such as memory scans
- Telemetry DLL; injected into each tracked process, gathers telemetry data and sends it to agent
- ETW consumer; receives very useful info about different kinds of events happening on the machine
- Kernel driver; protects the system from tampering and handles kernel callbacks to get informed on events like process creation
- Central server; gathers all endpoints' data for a centralized view and provides it to the UI, also forwards commands to agents
- UI; provides the operator a clear centralized view of alerts, telemetry data, and control over each endpoint

For the alpha version detection comes from the following scans:
- Static analysis of files when they are created, modified, or opened(loaded)
- Memory scanning with YARA. Different areas of memory scanned based on context; both periodic scans and event triggered scans
- Behavior patterns from API calls, filesystem operations, registry modification and more
- Basic thread scanning
- Network behavior

There are also multiple anti-tampering tactics in place:
- Heartbeat mechanism to insure hook DLL stays in place, to gather telemetry
- Periodic hash comparisons to detect removal of hooks and other kinds of patching
- Periodic IAT scans to detect unhooking and malicious hooking
- Self-integrity checks

I'm planning to add some additional scans in the future but these form the core for detections.
These scans depend on a few types of rules: YARA rules for static and memory scans, API behavior patterns, filesystem behavior patterns and registry behavior patterns (same format). You can use the default rules or add your own by adding files to rules/. The system is very dependent on good patterns and YARA rules!

This project is still in development and not yet ready for real use.
So far what is ready:
- A demo mode to track a manually specified program (no driver yet, so no auto-attach)
- API hooking and API pattern detection
- DLL injection detection through thread startroutine address
- Static analysis engine (integrated + standalone tool)
- Memory scanning (utilizing YARA-X)
- Behavioral pattern detection
- Telemetry DLL
- IAT hook detection
- Simple CLI
