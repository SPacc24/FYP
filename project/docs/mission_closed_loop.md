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

## Closing the loop on the console

1. **Validate safe queue** — marks all `queued_auto` auxiliaries executed (lab attestation or after real MSF runs).
2. **Approve** high-risk catalog actions — never auto-runs shells.
3. **Confirm impact** on approved rows — records outcome; does **not** silently set foothold.
4. **Attach foothold proof** — only this sets `foothold_proved` and unlocks pivot segment recommendations.
5. Debrief **confirmed findings** = proof count (not scanner noise). Partial goal when MS17 is suppressed without CVE is correct.
