# netscan

A tiny desktop app (Rust + Dioxus 0.7) that scans your local Wi-Fi /24 and draws the
network as a topology map in an Arasaka-style HUD. No settings: launch it and look.

## Run

    cargo run --release            # desktop window
    cargo run --release -- --cli   # scan once, print JSON (progress + timings on stderr)

## How it works

ICMP + TCP + UDP "touch" sweep -> ARP table -> IEEE OUI vendor lookup (`assets/oui.csv`),
mDNS, reverse DNS and public IP/ISP -> heuristic device classification.

## Limitations

- macOS only (uses `arp`, `route`, raw ICMP sockets).
- Phones using randomized (private) MACs show no vendor; they are guessed as mobile.
- Devices that are asleep or ignore ARP/ICMP/TCP will not appear.
- Only the local /24 is scanned; classification is heuristic.
