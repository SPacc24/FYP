<?php
// AutoPentest Lab Diagnostics - INTENTIONALLY VULNERABLE.
// Authorized, isolated lab use only. Do NOT deploy on any real or internet-facing host.
//
// The "host" parameter is passed straight into a Windows shell command, which is a
// deliberate OS command-injection weakness so the PenPilot controlled web validator
// can confirm command execution safely (it injects an arithmetic probe and checks the result).

$output = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['host'])) {
    $host = $_POST['host'];
    // Vulnerable on purpose: user input concatenated directly into an OS command.
    $output = shell_exec('ping -n 1 ' . $host . ' 2>&1');
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>AutoPentest Lab Diagnostics</title>
</head>
<body>
  <h1>AutoPentest Lab Diagnostics</h1>
  <p>Enter a host to run a connectivity check.</p>
  <form action="/diagnostics.php" method="POST">
    <label>Host: <input type="text" name="host" value="127.0.0.1"></label>
    <button type="submit">Run diagnostic</button>
  </form>
  <pre><?php echo htmlspecialchars($output === null ? '' : $output); ?></pre>
</body>
</html>
