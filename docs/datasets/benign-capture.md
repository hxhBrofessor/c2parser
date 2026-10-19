# Benign capture — intake checklist (v10a 1.3)

This capture sets every operating point. Thresholds are the benign 1 − 10⁻⁴
quantile, so the benign set is the denominator for every false-positive rate
c2parser reports. It stays outside the repo, like anything derived from it.
Tests and runs reach it through `C2PARSER_BENIGN`.

## What to capture

| Item | Requirement |
|---|---|
| Duration | 48–72 h, continuous (include one night and one weekday morning logon) |
| Hosts | One **Windows 11, domain-joined** (GPO, Windows Update, Defender, Office/Teams, Edge); one **Linux** with chrony, apt (unattended-upgrades) and a Prometheus node exporter being scraped; one **Jamf-managed Mac** |
| Capture point | SPAN/mirror port, or a host capture on each machine (`dumpcap`/`tcpdump`). Both are fine; say which in the notes |
| snaplen | full (`-s 0`). Truncated payloads hide HTTP, TLS and LDAP content |
| Segmentation | rotate at 1 GB (`dumpcap -b filesize:1000000` or `tcpdump -C 1000`). Keep the default sequential names, so name order = time order |
| Other activity | normal work only, **no deliberate C2, red-team tools or scanners**. If something unusual must run, write it in the notes with times |
| Event notes | a short log of notable events (below) |

Example commands:

```sh
# macOS / Linux host capture, rotated at 1 GB, full snaplen
sudo tcpdump -i en0 -s 0 -C 1000 -w benign-mac.pcap
# Windows (Wireshark's dumpcap), rotated at 1 GB
dumpcap -i Ethernet -s 0 -b filesize:1000000 -w C:\caps\benign-win11.pcapng
```

## Event notes (keep beside the capture as `notes.md`)

```
2026-10-20 09:02  Win11 logon (domain), VPN off
2026-10-20 13:30  Patch Tuesday: Windows Update + Office C2R update
2026-10-21 08:10  Mac on hotel Wi-Fi, VPN on 08:12–17:40
2026-10-21 22:00  apt unattended-upgrades run
```

Record: logons and reboots, patching (Patch Tuesday, apt, macOS updates),
VPN on/off, travel or network changes, sleep/wake, anything you ran that a
detector might see (a backup, a large sync, a remote-support session).

## Before running

1. Check the capture is complete: the segments should be continuous, with no gap in time between one file's last packet and the next file's first (`capinfos -ae benign-win11_*.pcapng`).
2. Write a manifest beside the data (not in the repo):

   ```yaml
   version: 2
   name: benign 72h
   internal: [10.0.0.0/8, 192.168.0.0/16]   # your LAN ranges
   captures:
     - path: win11/benign-win11_*.pcapng
       role: benign
       rotated: true
       licence: internal
       expected_host_hours: 72   # hosts × hours for this capture; the report flags > 10 % off
     - path: linux/benign-linux_*.pcap
       role: benign
       rotated: true
       licence: internal
       expected_host_hours: 72
     - path: mac/benign-mac*.pcap
       role: benign
       rotated: true
       licence: internal
       expected_host_hours: 72
   ```

   A SPAN capture of all three hosts is one entry with `expected_host_hours: 216`.
   Host-hours count every internal client with a scored series. Other LAN
   devices seen on the SPAN add to the measured figure, so set
   `expected_host_hours` to what you expect to see, or narrow `internal:`.

3. Validate, then run:

   ```sh
   c2parser eval -manifest ~/data/benign/manifest.yaml -check
   C2PARSER_BENIGN=~/data/benign c2parser eval -manifest ~/data/benign/manifest.yaml -out ~/data/benign/eval-out -j 4
   C2PARSER_BENIGN=~/data/benign go test ./internal/eval -run TestBenignManifest -v
   ```

## What the report gives

- FP per benign host-hour, per scorer at its operating point and per severity (critical/high/medium/low), each with a 95 % Poisson interval.
- Benign quantiles of every score and timing metric at 1 − 10⁻², 10⁻³, 10⁻⁴, with distribution-free intervals. "?" means the sample can't bound that side yet. A real 10⁻⁴ point needs ≥ 10,000 benign series, and these three hosts will give hundreds. That is expected: the report states it, and TQH-C2's background traffic adds to the denominator.
- The top 20 benign findings with their reasons: the list to review first.
- Destination prevalence: distinct internal clients per (destination, period bucket). With three hosts this mostly shows single-host pollers (the Prometheus scrape). It is reported only and does not feed scores.

## Handling

- Never commit the capture, the manifest's data paths or the per-series output (`series.csv`, `report.json`). Only aggregate tables (quantiles, rates) go into review docs.
- Licence: `internal`.
