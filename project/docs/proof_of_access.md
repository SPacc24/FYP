# Controlled Proof of Access

The proof-of-access scripts do not exploit a target or test credentials. They
only record a harmless JSON marker after the controller observes a successful,
completed CALDERA link for one of these ATT&CK technique families:

- `T1190` - Exploit Public-Facing Application
- `T1110` - Brute Force / weak-credential validation
- `T1078` - Valid Accounts

Discovery, failed, discarded, running, and timed-out links cannot receive a
ticket.

## Configuration

Set these values in `project/.env` and restart the Flask application:

```env
PROOF_OF_ACCESS_ENABLED=true
PROOF_OF_ACCESS_SECRET=replace-with-at-least-32-random-characters
PROOF_OF_ACCESS_TTL=300
```

The controller returns a short-lived ticket in
`proof_of_access.tickets` after a qualifying operation. Store one ticket in a
temporary text file on the validated host, then run the matching wrapper:

The validator URL must be reachable from that host. Keep it restricted to the
authorised lab network or publish only this endpoint through an authenticated,
access-controlled reverse proxy; the Flask development server is local-only by
default and should not be exposed directly.

```powershell
.\proof_of_access\record_proof.ps1 `
  -TicketFile .\ticket.txt `
  -ValidatorUrl http://CONTROLLER:5000/proof-of-access/redeem
```

```sh
./proof_of_access/record_proof.sh \
  ./ticket.txt \
  http://CONTROLLER:5000/proof-of-access/redeem
```

The script sends the ticket and local hostname to the controller. The
controller verifies the signature, expiry, operation/link success, hostname,
CALDERA agent source address when available, and one-time-use state. Only then
does the script write a JSON marker under `./proof-of-access/`.

The marker contains operation, link, technique, host, completion-time, and
digest metadata. It never stores commands, output, passwords, hashes, tokens,
or other collected target data.
