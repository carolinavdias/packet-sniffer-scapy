<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/icon-dark.svg">
  <img src="assets/icon-light.svg" height="110" alt="">
</picture>

<h1>𝙋𝙖𝙘𝙠𝙚𝙩 𝙎𝙣𝙞𝙛𝙛𝙚𝙧</h1>
<h3>Live Network Traffic Analyser</h3>

![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Scapy](https://img.shields.io/badge/Scapy-1B3A57?style=for-the-badge)
![Linux](https://img.shields.io/badge/Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black)

*Academic project developed for **Redes de Computadores** @ University of Minho*  
*Project grade: **18.5/20** ⭐*

</div>

---

## 📡 About

For Computer Networks we built a packet sniffer in Python with Scapy. It listens on a network interface, catches every frame that goes by and tells you what it is: ARP, ICMP, TCP or UDP, who sent it, where it's going and on which port.

The base project asked for protocol, IP and MAC filters and two output modes (live in the console or saved to a log). We ended up going quite a bit further and added **11 optional features**, from kernel level filtering to a little web dashboard to look at the results.

---

## ⚡ What it does

| # | Optional feature | How to use it |
|---|---|---|
| 1 | Coloured statistics at the end | stop the capture with `Ctrl+C` |
| 2 | Average RTT from ICMP pings | automatic |
| 3 | Protocol distribution chart | `--graph` |
| 4 | DNS resolver with cache and top hostnames | automatic |
| 5 | Port scan and ICMP flood detection | automatic |
| 6 | Capture for a limited time | `--duration 60` |
| 7 | Port numbers shown as service names | automatic |
| 8 | Native BPF filters, applied by the kernel | `--bpf 'tcp port 443'` |
| 9 | Interactive menu, with the capture running in its own thread | run with no arguments |
| 10 | Hashtable index for instant filtering after the capture | `--fproto`, `--fdport`, ... |
| 11 | HTML dashboard | open it in the browser |

---

## 🧩 My part

I took care of Part B, the optional features, and of exporting the session reports with `--save`. In the report I wrote the architecture, the optional features, the analysis on a real network interface and the limitations, and I kept the group organised along the way.

---

## 🔍 The fun part

The part I'm proudest of is the post capture filtering. Instead of going through every packet each time you filter, the sniffer keeps them indexed in a hashtable by protocol, address and port while it captures. Filtering afterwards is just crossing a few buckets, so it's instant even after thousands of packets.

My favourite bug: the port scan detector only went off if someone hit **exactly** 15 ports. One more and it stayed quiet. A `==` that should have been `>=`.

---

## 🚀 How to Run

```bash
# Install
sudo pip3 install scapy --break-system-packages
pip install matplotlib --break-system-packages    # only needed for --graph

# Interactive menu
sudo python3 sniffer.py

# Or straight from the command line
sudo python3 sniffer.py -i wlp2s0 --live -l capture.txt
sudo python3 sniffer.py -i eth0 --live --bpf 'tcp port 443' --duration 60 --graph
sudo python3 sniffer.py -i wlp2s0 --duration 30 --fproto TCP --fdport 443
```

---

## 🎛️ Parameters

| Parameter | Example | What it does |
|---|---|---|
| `-i` | `-i eth0` | Interface to listen on |
| `-p` | `-p tcp` | Protocol filter (`arp`, `icmp`, `tcp`, `udp`) |
| `--ip` | `--ip 192.168.1.1` | Source or destination IP filter |
| `--mac` | `--mac aa:bb:cc:dd:ee:ff` | MAC address filter |
| `--bpf` | `--bpf 'tcp port 443'` | tcpdump style BPF expression |
| `--live` | `--live` | Shows packets in real time |
| `-l` | `-l capture.txt` | Saves packets to a log file |
| `--save` | `--save session.txt` | Exports a full report at the end |
| `--graph` | `--graph` | Protocol chart at the end |
| `--duration` | `--duration 60` | Stops after N seconds |
| `--fproto` `--fsrc` `--fdst` | `--fproto TCP` | Filters applied after the capture |
| `--fsport` `--fdport` `--fmin` `--fmax` `--fhi` `--fhf` | `--fdport 443` | More filters: ports, packet size and time window |

---

## 🗂️ Project Structure

```
.
├── sniffer.py               # capture, parsing, filters, stats and menu
├── sniffer_dashboard.html   # web dashboard
└── RC-TP2-PL4.pdf           # project report (in Portuguese)
```

---

## 🛠️ Tech Stack

`Python` · `Scapy` · `BPF` · `Threading` · `Hash Tables` · `matplotlib` · `CORE Emulator`

---

## 👩‍💻 Authors

**Carolina Dias** · [@carolinavdias](https://github.com/carolinavdias)  
**Ana Patrícia Machado** · [@apatriciamachado](https://github.com/apatriciamachado)  
**Rúben Oliveira** · [@rubCoder](https://github.com/rubCoder)

<p align="center"><i>no packets were harmed in the making of this project</i></p>
