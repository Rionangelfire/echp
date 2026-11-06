# Echp

Nova Echo AI simulator and IOC monitor, built with Copilot and Gemini as HTML sims and Python tooling.

## Files

- **continuum-interface.html** — "Echp: The Continuum Interface." Gemini-powered chat plus a tactical game UI: threat monitor, incident log, and missions with SCAN / PURGE / ISOLATE / DECRYPT / REBOOT commands. Needs a Gemini API key to run — the key field in the file is empty.
- **echo-intelligence.html** — "Echo Intelligence." A simpler Echp chat terminal, same Gemini model. Also needs an API key.
- **ioc_monitor.py** — UDP syslog listener (port 514) that extracts IPs, domains, and MD5 hashes from log lines, matches them against a known-IOC set, and writes JSON alerts to `ioc_alerts.log`, sends email alerts via Yahoo SMTP, and prints SIEM JSON. The IOCs in the file are placeholders, not live threat intel — replace them before relying on it. The Yahoo app password is **not** in the file; set it as the `YAHOO_APP_PASSWORD` environment variable.

## Status

Working sims and a working monitor script. The monitor's `match_iocs()` implementation was added Nov 5, 2026 (it was missing from the original paste and the script crashed without it). Real IOCs and a Gemini API key are still needed before either piece does live work.
