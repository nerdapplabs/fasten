#!/bin/sh
# Regenerate go/xlang_vectors.json by sealing through Python's PUBLIC path.
# The vectors MUST be produced by the SDK, never hand-written — a hand-pinned
# constant compares Go against Go and cannot detect the two SDKs diverging.
set -eu
cd "$(dirname "$0")/.."
docker run --rm -v "$PWD":/w -w /w/python \
  -e FASTEN_CORE_LIB=/w/fasten-core/target/release/libfasten_core.so \
  python:3.12-slim sh -c "pip install -q -e '.[sqlite]' && python3 - <<'PY'
import json
from datetime import datetime, timezone
from fasten.attrs import AuditRow
from fasten.chain import seal
out=[]
for label, ts in [
    ('micros',       datetime(2026,6,15,10,30,45,123456, tzinfo=timezone.utc)),
    ('whole_second', datetime(2026,6,15,10,30,45,0,      tzinfo=timezone.utc)),
    ('one_micro',    datetime(2026,6,15,10,30,45,1,      tzinfo=timezone.utc)),
]:
    r = AuditRow(id='evt-abc123', origin_id='evt-abc123', monotonic_seq=1, timestamp=ts,
        code='ORDER_PLACED', action='create', severity='info', service_id='gateway',
        source_node_id='node-1', tenant_id='tenant-x', actor='alice', actor_kind='user',
        target='order/42', category='order', domain='sales', method='http',
        request_id='req-xyz', detail={'qty':3,'sku':'WIDGET'})
    out.append({'label':label,'row':seal('genesis', r).to_dict()})
print(json.dumps(out, indent=1))
PY" > go/xlang_vectors.json
echo "regenerated go/xlang_vectors.json"
