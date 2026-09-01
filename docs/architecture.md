# Architecture Baseline

The workspace follows a strict dependency direction:

`platform -> core -> {audio, crypto, protocol}`

UI adapters, including the planned Slint application, depend on `core` and
platform adapters. Protocol and crypto crates remain independent of the UI and
of Qt-era implementation details.

Audio paths must use bounded queues. When a queue is full, stale frames are
discarded instead of creating unbounded latency. This matches the
transceiver-style real-time requirement.

The initial desktop binary is deliberately minimal. It confirms workspace
packaging without committing the project to an early UI or audio-backend
choice.
