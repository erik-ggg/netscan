# netscan

A tiny desktop app (Rust + Dioxus 0.7) that scans your local Wi-Fi /24 and draws the
network as a topology map in an Arasaka-style HUD. No settings: launch it and look.

## Run

    cargo run --release            # desktop window
    cargo run --release -- --cli   # scan once, print JSON (progress + timings on stderr)

## How it works

ICMP + TCP + UDP "touch" sweep -> ARP table -> IEEE OUI vendor lookup (`assets/oui.csv`),
mDNS, reverse DNS and public IP/ISP -> heuristic device classification.

## Deep intel

Click a device on the map to run a deep scan and open its dossier. Probed: ICMP echo
(RTT/TTL), 36 common TCP ports, service banners, HTTP title/server, RTSP, NetBIOS and
UPnP descriptors; results feed an OS guess and exposure notes. Keys: `ESC` close/abort,
`R` re-scan (in the dossier), `M` mute audio (synthesized, low, on by default).
Headless: `cargo run --release -- --intel <ip>` prints the scan events and a JSON dossier.

Safety: only hosts inside your own subnet are ever probed; it uses TCP connects plus
standard benign requests (HTTP GET/HEAD, RTSP OPTIONS, NetBIOS status) and reads banners
without sending anything to them. A beacon phase also connects to ~16 smart-TV control
ports on in-subnet hosts and reads the public identity endpoints (Cast `eureka_info`, Roku
ECP `device-info`, Samsung `/api/v2/`, Philips `/6/system`) plus a unicast DIAL search;
self-signed certificates are accepted only on 8443/8002/1926, redirects are never followed
and bodies are capped at 32 KiB. No pairing, no logins, brute force or exploitation.

## Neural link

In a dossier, `C` (or the CONNECT button) opens the LINK CONFIG drawer: pick a way in (ADB,
wireless-debugging PAIR, SSH, LOCAL), review the exact command, press ENGAGE. A full-screen
console opens with a real terminal (xterm.js on a PTY running your own `$SHELL`); the link
command is *typed* into it, so you see everything and land in a shell with `$TV_HOST`,
`$NETSCAN_TARGET` and `$NETSCAN_DATA` set when it ends.

Keys in the console: everything goes to the terminal (ESC, Ctrl+C, `r`, `m` included);
`Ctrl+]` or the SEVER button closes the link and kills the PTY (and runs `adb disconnect`
for ADB links); `Cmd+C` / `Cmd+V` copy and paste. `Cmd+W` quits the whole app.

Safety: targets must be inside your own subnet; commands are built only from validated values
(IP, numeric ports, a checked user name, a 6-digit code), never from device-provided strings.
No credentials are stored or auto-typed: passwords and SSH host-key prompts are answered in the
terminal. netscan only prepares commands for the selected target. For Android/Google TVs a
PAYLOAD drawer *types* (never runs) the [cleanyourtv](https://github.com/Gathin23/cleanyourtv)
steps (MIT, (c) Gathin23); PURGE asks for confirmation first. The adb server daemon is left
running (it is shared with other tools). Missing `adb`: `brew install --cask android-platform-tools`.

Third-party: [xterm.js](https://github.com/xtermjs/xterm.js) 6.0.0 and its fit addon 0.11.0 are
vendored in `assets/vendor/xterm/` under the MIT license (notices included).

## Limitations

- macOS only (uses `arp`, `route`, raw ICMP sockets).
- Phones using randomized (private) MACs show no vendor; they are guessed as mobile.
- Devices that are asleep or ignore ARP/ICMP/TCP will not appear.
- Only the local /24 is scanned; classification is heuristic.
