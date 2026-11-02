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
without sending anything to them. No logins, brute force or exploitation.

## Limitations

- macOS only (uses `arp`, `route`, raw ICMP sockets).
- Phones using randomized (private) MACs show no vendor; they are guessed as mobile.
- Devices that are asleep or ignore ARP/ICMP/TCP will not appear.
- Only the local /24 is scanned; classification is heuristic.
