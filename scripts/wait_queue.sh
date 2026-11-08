#!/usr/bin/env bash
# Waits until the audit queue is empty (or the server stops), then prints a summary.
cd "$(dirname "$0")/.."
J=$(mktemp)
python3 -c "import json;print(json.dumps({'user':'admin','password':open('runs/.admin_password').read().strip()}))" \
  | curl -s -c "$J" -o /dev/null -XPOST -H 'content-type: application/json' -d @- http://127.0.0.1:8000/api/auth/login
while curl -s -o /dev/null http://127.0.0.1:8000/api/health; do
  n=$(curl -s -b "$J" http://127.0.0.1:8000/api/admin/stats | python3 -c "import sys,json;t=json.load(sys.stdin)['totals'];print(t['queued']+t['running'])" 2>/dev/null)
  [ "$n" = "0" ] && break
  sleep 15
done
curl -s -b "$J" http://127.0.0.1:8000/api/admin/stats | python3 -c "
import sys,json;d=json.load(sys.stdin);print(d['verdicts']);print(d['totals'])
for r in d['rows'][:${1:-200}]: print(r['verdict'] or r['status'], r['host'], r['after_reject'], r['before_choice'], r['vendors'][:4], (r['headline'] or '')[:90])"
rm -f "$J"
