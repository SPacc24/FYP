# v32.4 UI and Report Readability Updates

- Live scan overview row now shows target, current task, next task, and scan profile.
- Command log output opens in a modal with the full command, purpose, captured output, and evidence file path.
- Results page uses card-based confirmed CVE findings instead of a very wide table.
- Evidence collection rows use a modal viewer for command/output instead of squeezing long commands into narrow table columns.
- Additional Relevant Evidence hides context-not-applicable CVE records instead of displaying them to users.
- PDF report download now falls back to a ReportLab-generated PDF if WeasyPrint fails in the local Kali environment.
