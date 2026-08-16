# Demo pivot reliability fixes

This revision keeps the existing MS17-010/EternalBlue, Metasploit, and exploitation workflow unchanged.

Fixed:
- valid Chisel reverse-server syntax;
- explicit reverse SOCKS client mapping (`R:1080:socks`);
- preference for a preinstalled Ubuntu Chisel binary, with HTTP download fallback;
- separate server-running and SOCKS-ready status;
- internal scans blocked until the Ubuntu client has created the SOCKS listener;
- project-local ProxyChains configuration retained;
- configurable pivot ports and internal CIDR ranges;
- web exploit parameter environment-variable typo;
- `type(exc).__name__` in the full-chain script;
- pivot scan results continue to persist into the active assessment/dashboard state.

The existing EternalBlue command and catalog entries remain present.
