# Mission closed-loop guide

## One-liner

Evidence → safe auto → branch on dead paths → human gate for impact → proof before pivot → debrief.

## Playbooks

- `edge_to_internal_proof` — full product narrative
- `surface_validation_only` — map + validate only

Edit JSON under `policies/playbooks/`. Reload is automatic (loader cache is small; restart app after edits if needed).

## Adding a technique (no Python hardcoding)

1. Add entry to `policies/exploit_module_catalog.json` (`metasploit_modules`, `web_profiles`, or `lateral_techniques`) with a `match` rule.
2. Optionally add branch/detector rows in the playbook JSON.
3. Restart / run tests.

## API smoke

```bash
curl -s localhost:5000/api/mission/playbooks
curl -s -X POST localhost:5000/api/mission/start -H 'Content-Type: application/json' -d '{
  "playbook_id":"edge_to_internal_proof",
  "parsed_results":{"target":"10.10.10.20","hosts":[{"ip":"10.10.10.20","ports":[
    {"port":80,"state":"open","service":"http"},
    {"port":445,"state":"open","service":"microsoft-ds"}
  ]}]}
}'
```

(Requires operator session when `OPERATOR_TOKEN` is set.)
