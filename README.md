![Workflow Status](https://github.com/mcckyle/hostRecon/actions/workflows/cpp.yml/badge.svg)

# hostRecon

## Intelligent Local Network Discovery with libpcap

## Overview

**hostRecon** is a simple, lightweight, CLI-based network scanner for discovering active hosts on local networks. Powered by `libpcap`, it performs low-level packet injection and capture for precise and reliable network reconnaissance. This tool is ideal for developers, sysadmins, cybersecurity enthusiasts seeking a deeper look at the devices on their LAN.

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Build](#usage)
- [Current State](#current-state)
- [Future State](#future-state)
- [Contributing](#contributing)
- [License](#license)

## Features

- **Accurate Host Detection**: Uses ARP and ICMP scanning to identify active devices on the local network.
- **Low-Level Network Access**: Builds and injects Ethernet, IP, and ICMP frames directly with `libpcap`.
- **Real-Time Output**: Displays responsive hosts immediately during scanning.
- **Error-Resilient**: Gracefully handles interface, packet, and permission-related failures.
- **Extensible Architecture** - Clean, modular design for future protocol and feature expansion.

## Installation

### Requirements

To run **hostRecon**, you will need the following:

- **[libpcap](https://www.tcpdump.org/)** - For packet capture/injection:
  - Ubuntu/Debian: ```bash sudo apt install libpcap-dev```
  - Fedora: ```bash sudo dnf install libpcap-devel```
  - macOS: ```bash brew install libpcap```

- **C++17 or newer** compiler (`g++`, `clang++`, etc.):

- **CMake** (optional, but recommended).

### Build

1. Clone this repository:

   ```bash
   git clone https://github.com/mcckyle/hostRecon.git
   cd hostRecon
   ```

2. Create a `build` directory and navigate into it:

   ```bash
   mkdir build
   cd build
   ```

3. Compile the project using CMake:

   ```bash
   cmake ..
   make
   ```

4. Run the scanner with appropriate privileges (usually as root):

   ```bash
   sudo ./networkScanner
   ```

5. (Optional) Run the tests:

   To run the tests, execute the following:

   ```bash
   ./test_network_scanner
   ```

## Usage

Simply execute

```bash
sudo ./networkScanner
```

**hostRecon** automatically identifies your active network interfaces and scans the
local subnet for reachable hosts. Each responsive device is printed in real-time, showing its IP and MAC address.

## Current State

As of now, **hostRecon** provides the following functionality:

- Direct ARP-based host discovery on local networks.
- ICMP echo (ping) scanning for active device verification.
- Real-time result display with informative status output.
- Reliable interface initalization and error handling.

### Known Limitations:
- **Single-threaded Scanning**: Scans hosts sequentially, which may limit speed in larger networks.
- **Routed Scanning**: Focused on local subnet (no routed scanning, yet).

## Future State

In future releases, we plan to add:

- **Multi-threaded Support**: Enable concurrent pinging for faster scans, improving efficiency.
- **Configurable Subnets**: Allow users to specify the IP range and subnet dynamically.
- **Expanded Protocols**: Include TCP/UDP port scanning and other protocols.
- **Detailed Reporting**: Enhance reporting features, providing additional data like response times and packet loss.
- **Improved Error Handling**: Offer better feedback for various network-related errors.
- **Graphical User Interface (GUI)**: Implement a GUI for a more user-friendly experience.

## Contributing

We welcome contributions from the community! Whether it’s submitting bug reports, suggesting new features, or contributing code, your input is valuable. Please refer to the [CONTRIBUTING.md](CONTRIBUTING.md) file for guidelines on how to contribute.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
