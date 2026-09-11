# PES6_LAN_Play

[![العربية](https://img.shields.io/badge/README-العربية-2ea44f?style=for-the-badge)](README.ar.md)

Play PES6 over LAN using a lightweight local host server and a generated Windows XP helper script.

## What this script does

`pes6_lan.py` runs a local PES6-compatible LAN server on the host machine and generates XP helper files.

It handles:
- PES6 LAN service endpoints (TCP + STUN)
- LAN-only gateway/STUN redirection via `hosts`
- LAN-only firewall opening for the game UDP port
- XP helper generation: `PES6_XP_CONNECT.cmd` and `PES6_XP_UNDO.cmd`

## How it works

1. Start `pes6_lan.py` on the host.
2. The host script detects/uses a LAN IPv4 and UDP game port (default `5739`).
3. On Windows host, it can auto-configure host `hosts` + firewall rules (unless `--no-setup`).
4. It generates XP scripts in `win_xp_generatedScripts/` (or `--output-dir`).
5. Run `PES6_XP_CONNECT.cmd` once as Administrator on the XP guest.
6. Both PCs connect in-game to `Network -> (any non-empty password) -> Player -> PES6 LAN -> LAN`.

All profiles/rooms/settings are currently in RAM only and are cleared when the server stops.

## Installation and setup (both devices)

### 1) Host PC (baseline: Windows 10/11)

Requirements:
- Python 3.x
- Administrator rights for automatic host setup (hosts/firewall)

Run:
```bash
py pes6_lan.py
```

Optional flags:
```bash
py pes6_lan.py --ip 192.168.1.10
py pes6_lan.py --udp-port 5739
py pes6_lan.py --no-setup
py pes6_lan.py --undo
py pes6_lan.py --debug
py pes6_lan.py --self-test
```

### 2) Guest PC (baseline: Windows XP)

Requirements:
- No Python needed
- Administrator account

Steps:
1. Copy `PES6_XP_CONNECT.cmd` to XP.
2. Run it once as Administrator.
3. Start PES6 and enter LAN mode as shown above.

Undo on XP:
```cmd
PES6_XP_CONNECT.cmd --undo
```
or use `PES6_XP_UNDO.cmd`.

## Very important note

> **Current baseline design is:**
> - **Host:** Windows 10/11 (supported)
> - **Guest:** Windows XP
>
> Contributions are highly welcome to improve and extend the script for both host-side types/environments.
>
> Another strongly requested improvement is to add JSON-based persistence on the host to keep progress and player profiles between restarts.

## Security and network scope

- LAN only.
- Do not expose/forward server ports to the public internet.
- The script is intended for compatible local setups of PES6.

## Credits

Protocol work is based on:
- https://github.com/juce/fiveserver
