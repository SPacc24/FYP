# Critical fixes applied

- Fixed Mission API URL construction and added CSRF/error handling for Approve/Deny.
- Approved Metasploit mission actions now resolve against the current scan, execute through the existing policy gate, persist the run, and feed the outcome back into the mission.
- WinRM 5985 is matched by port before the generic `http` banner.
- Mission catalog suppresses clearly incompatible legacy-Windows checks and enforces canonical SMB port 445 for MS17-010/PsExec.
- Metasploit result cards now separate outcome, access gained, next step, and hidden technical details.
- CALDERA rows now show operator-readable evidence first; commands/raw stdout are collapsed.
- Added evidence-based fallback remediation when CALDERA-specific remediation is absent.
- Added an optional bounded lab credential audit using Kali `smbclient`: private targets only, explicit credential-pair file, maximum 10 attempts, delay between attempts, 0600 local cache. A discovered credential is reused by SMB validation and approved PsExec.

## Optional bounded credential audit

`.env`:

```env
ENABLE_LAB_CREDENTIAL_AUDIT=1
LAB_CREDENTIAL_AUDIT_FILE=/home/kali/FYP/lab_smb_pairs.txt
LAB_CREDENTIAL_AUDIT_MAX_ATTEMPTS=8
LAB_CREDENTIAL_AUDIT_DELAY_SECONDS=1.5
```

Credential file format:

```text
labuser:LabPassword1!
Administrator:YourKnownLabPassword
```

Use only accounts and targets created for the authorised lab. The implementation deliberately does not use RockYou or unlimited spraying.
