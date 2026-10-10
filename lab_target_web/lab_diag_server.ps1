# AutoPentest Lab Diagnostics - self-contained vulnerable web server (PowerShell).
# Authorized, isolated lab use ONLY. Serves the diagnostics page and, on POST to
# /diagnostics.php, passes the "host" field straight into a Windows shell command
# (intentional OS command injection) so PenPilot's web validator can confirm execution.

$ErrorActionPreference = 'Stop'

$listener = New-Object System.Net.HttpListener
$listener.Prefixes.Add('http://+:80/')
$listener.Start()

$template = @'
<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>AutoPentest Lab Diagnostics</title></head>
<body>
  <h1>AutoPentest Lab Diagnostics</h1>
  <p>Enter a host to run a connectivity check.</p>
  <form action="/diagnostics.php" method="POST">
    <label>Host: <input type="text" name="host" value="127.0.0.1"></label>
    <button type="submit">Run diagnostic</button>
  </form>
  <pre>__OUTPUT__</pre>
</body>
</html>
'@

function Encode-Html([string]$s) {
    if ($null -eq $s) { return '' }
    return $s.Replace('&','&amp;').Replace('<','&lt;').Replace('>','&gt;')
}

while ($listener.IsListening) {
    try {
        $ctx = $listener.GetContext()
        $req = $ctx.Request
        $res = $ctx.Response
        $output = ''

        if ($req.HttpMethod -eq 'POST') {
            $reader = New-Object System.IO.StreamReader($req.InputStream, $req.ContentEncoding)
            $body = $reader.ReadToEnd()
            $reader.Close()

            $hostVal = ''
            foreach ($pair in ($body -split '&')) {
                $kv = $pair -split '=', 2
                if ($kv.Length -eq 2 -and $kv[0] -eq 'host') {
                    $hostVal = [System.Uri]::UnescapeDataString(($kv[1] -replace '\+', ' '))
                }
            }

            # INTENTIONALLY VULNERABLE: user input concatenated into an OS command.
            $output = (cmd /c "ping -n 1 $hostVal 2>&1" | Out-String)
        }

        $page = $template.Replace('__OUTPUT__', (Encode-Html $output))
        $buffer = [System.Text.Encoding]::UTF8.GetBytes($page)
        $res.ContentType = 'text/html'
        $res.ContentLength64 = $buffer.Length
        $res.OutputStream.Write($buffer, 0, $buffer.Length)
        $res.OutputStream.Close()
    } catch {
        try { $res.Abort() } catch {}
    }
}
