# VS Code / non-Kali run preparation

This build can run the Flask UI and report pipeline from Visual Studio Code on Windows, Linux, or macOS.

Live reconnaissance still depends on external recon tools being installed on the host. The app now detects missing tools and reports them cleanly instead of crashing.

## Windows / VS Code setup

```powershell
cd AutoPenTest_Recon_Autonomous_Update_v32_8_from_v31
powershell -ExecutionPolicy Bypass -File .\install_windows.ps1
```

Then open the folder in Visual Studio Code and run:

```text
Run and Debug -> Run AutoPenTest Recon Flask App
```

Open:

```text
http://127.0.0.1:5000
```

## Required for meaningful live scans

At minimum, install and expose these in PATH:

```text
Python 3.10+
Git
Nmap
```

Recommended optional tools:

```text
gobuster
hydra
ssh-audit
smbclient
enum4linux-ng
smbmap
ProjectDiscovery httpx
```

If those optional tools are missing, the report will show the relevant check as unavailable or skipped. The UI and report generation still run.

## Honest limitation

Running from VS Code is supported. Running every Linux/Kali recon binary natively on Windows is not guaranteed unless those tools are installed or provided through WSL/Docker. The project is prepared so tool absence is handled professionally and does not break the application.
