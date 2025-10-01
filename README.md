---
# Networking

A comprehensive collection of C-based programs and resources for learning and exploring computer networking and network security. This repository is designed for students, hobbyists, and professionals who want to understand network protocols, experiment with real-world attacks (in a safe and ethical setting), and build or analyze network utilities.

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Directory Structure](#directory-structure)
- [Getting Started](#getting-started)
- [Disclaimer](#disclaimer)
- [License](#license)

---

## Overview

This repository brings together practical networking concepts by offering hands-on code examples and tools. It covers a range of topics, including low-level socket programming, packet sniffing, port scanning, denial-of-service (DoS) techniques, and building simple web servers.

Whether you want to understand how network attacks are executed, study the OSI model, or serve static HTML from a C webserver, this repo has resources to get you started.

---

## Features

- **DoS Attack Demonstrations:**  
  Source code showing how common DoS attacks (like SYN flood and RST hijack) are implemented. Use these only for learning or legal research purposes.

- **Packet Sniffers:**  
  Tools for capturing and decoding network packets with both raw sockets and `libpcap`, helping you see what’s happening on the wire.

- **Port Scanning:**  
  Code for scanning network ports, with stealth techniques included.

- **Tiny Web Server:**  
  Minimalist web server (`tinyweb.c`) that serves files from the `webroot` directory. Great for learning HTTP basics or embedded use.

- **Network Utilities:**  
  Host lookup, server utilities, and useful header files to streamline network programming.

- **Reference Materials:**  
  Includes command summaries and notes on networking concepts like the OSI model.

- **Ready-to-Use Configurations:**  
  VSCode settings for quickly setting up your development environment.

---

## Directory Structure

```
.
├── .HEADER                # Miscellaneous header/info
├── .gitattributes
├── .vscode/               # VSCode project settings
│   ├── c_cpp_properties.json
│   ├── launch.json
│   └── settings.json
├── DoS/                   # DoS attack code & docs
│   ├── attacks
│   ├── rst_hijack.c
│   └── synflood.c
├── OSI                    # OSI model info
├── README.md
├── commands               # Networking commands reference
├── hacking-network.h      # Shared headers for hacking tools
├── hacking.h              # Miscellaneous hacking utilities
├── host_lookup.c
├── scan/                  # Network scanning tools
│   └── shroud.c
├── server.c               # Simple TCP server
├── sniff/                 # Packet sniffers & helpers
│   ├── decode_sniff.c
│   ├── hacking-network.h
│   ├── hacking.h
│   ├── pcap_sniff.c
│   └── raw_tcpsniff.c
├── tinyweb.c              # Minimal web server
├── webroot/               # Static web content
│   ├── favicon.ico
│   ├── image.jpg
│   └── index.html
└── webserver_id.c         # Web server identification tool
```

---

## Getting Started

1. **Clone the Repo:**
   ```bash
   git clone https://github.com/rKeshaw/Networking.git
   cd Networking
   ```

2. **Build the Tools:**  
   Most C files can be compiled with `gcc`. For example:
   ```bash
   gcc -o tinyweb tinyweb.c
   gcc -o synflood DoS/synflood.c
   ```

3. **Run with Caution:**  
   - These tools are powerful and can disrupt networks.
   - Always use them in a controlled, legal, and ethical environment (such as your own lab or test VMs).

4. **Check Dependencies:**  
   - Some tools (like packet sniffers using `libpcap`) may require additional libraries:
     ```bash
     sudo apt-get install libpcap-dev
     ```
   - For Windows, use MinGW or WSL and ensure required libraries are available.

5. **Explore:**  
   - Read the source code to understand how each tool works.
   - Modify and extend to fit your own learning goals.

---

## Disclaimer

**This repository is for educational and ethical research purposes only.**  
Do NOT use these tools or techniques on systems or networks you do not own or have explicit permission to test. The repository author and contributors are not responsible for any misuse or damage caused.

---

