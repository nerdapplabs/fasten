"""
Shims — opt-in per transport. Each shim does one thing: read an id from the
wire, set it as ambient context, call downstream. ~10 lines each.

Bundled:
  - http             (X-Request-ID)
  - mqtt             (_req in payload)
  - scheduler        (mint scheduler-<run_id>)
  - deploy_pipeline  (X-Deploy-ID piggyback)
  - agent_tool       (AI agent tool-call ctx)

Adopters on other wires (gRPC, NATS, AMQP, …) write the same 10-line pattern.
"""
