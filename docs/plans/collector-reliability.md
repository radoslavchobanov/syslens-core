# Collector reliability implementation

Scope: implement the first reliability milestone from the application review.
Preserve schema version 1, MQTT topics, CLI compatibility, standalone operation,
and the existing private-memory changes. Do not implement diagnosis, fleet
storage, new external adapters, or deploy services in this change.

## Tasks and acceptance criteria

1. Safe history ownership
   - Protect persisted history with an advisory single-writer lock held across
     load, mutation, and save. Never replace a live writer's state with a stale
     independently loaded copy. Local views remain usable while the agent owns
     history; they may update an ephemeral copy without saving it.
   - Use unique owner-only temporary files, atomic replacement, surfaced errors,
     and safe handling of malformed history. Preserve existing history format.
   - Cover competing writers, malformed history, and persistence round trips.

2. Continuous collection and correct process views
   - Extract a reusable collector with retained counter readings for repeated
     samples; compute rates over the actual measured counter interval. Keep the
     explicit warm-up window for standalone snapshots.
   - Sort typed process measurements before JSON serialization. Keep the legacy
     CPU-ranked top-N output for normal snapshots and MQTT, while the TUI can
     sort the complete process set by CPU or private memory.
   - Run TUI sampling outside its input/render loop with bounded communication
     and reliable worker shutdown. Avoid catch-up bursts when collection is slow.
   - Validate sample-window inputs; test process ranking, PID reuse, elapsed-time
     rate calculations, and collector scheduling where practical.

3. Resilient MQTT lifecycle
   - Keep host collection and history alive through initial broker unavailability
     and later disconnects. Reconnect with capped exponential backoff and jitter.
   - Bound queued state, preferring the latest snapshot during an outage.
   - Republish metadata and online availability on reconnect. For --once, wait
     for the configured QoS completion (acknowledgement for QoS 1/2) with a finite
     timeout, and return failure on timeout or failed delivery.
   - Handle SIGINT/SIGTERM with final state save and bounded, best-effort offline
     publication and clean disconnect. Do not require a public/live broker.
   - Test lifecycle behavior against an isolated local broker or protocol fixture.

4. Regression gates and documentation
   - Add PR/push CI for formatting, Clippy, and tests; gate release builds on tests.
   - Add CLI/JSON compatibility smoke coverage and document new ownership,
     collection, and transport behavior accurately.
   - Verify debug/release builds and local CLI behavior using isolated state;
     preserve original workspace edits when handing back the completed change.

## Workflow

Use a fresh implementation subagent for each task, followed by an independent
specification review and then a code-quality review. Resolve findings before
starting the next task. Finish with a review of the combined changes.

## Progress

- Baseline: existing user edits copied into isolated worktree and committed.
- Task 1: implemented, specification and code-quality reviews passed.
- Task 2: implemented, specification and code-quality reviews passed.
- Task 3: implemented, specification and code-quality reviews passed.
- Task 4: implemented, specification review passed; pending code-quality re-review.
