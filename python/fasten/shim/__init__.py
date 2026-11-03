"""Optional integrations that carry the request id across a transport, or
feed other logging libraries into fasten.

  http        X-Request-ID middleware and the api log middleware
  mqtt        ``_req`` field in JSON payloads
  scheduler   a ``scheduler-<run_id>`` id per job run
  stdlib      ``logging`` handler
  structlog   structlog processor and setup
"""
