#!/bin/bash
# Juice Shop end-to-end replicates with the per-endpoint IDOR ceilings (measures live false triggers).
cd /c/Users/denny/Documents/AI-CySec-defence-system
export AEGIS_MANIFEST_KEY_FILE=$(cygpath -w "$HOME/.aegis/manifest.key")
export AEGIS_ADMIN_TOKEN_FILE=$(cygpath -w "$HOME/.aegis/admin.token")
mkdir -p logs/rep12
S=logs/rep12/status
: > $S
for i in 1 2 3; do
  echo "e2e juice rep $i $(date +%H:%M)" >> $S
  .venv/Scripts/python.exe eval/e2e_live.py --no-cold > logs/rep12/e2e_$i.out 2>&1
  cp logs/e2e_summary.json logs/rep12/e2e_$i.json; cp logs/controller/e2e_events.jsonl logs/rep12/e2e_$i.events.jsonl
done
echo "DONE $(date +%H:%M)" >> $S
