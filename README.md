# C++ Modbus MITM Tool

## Description

This tool performs a Man-in-the-Middle (MITM) attack targeting Modbus TCP traffic between a Programmable Logic Controller (PLC) and a Human-Machine Interface (HMI). It allows for the interception and on-the-fly modification of specific Modbus commands. This project is a C++ implementation, aiming for higher performance and lower overhead compared to similar tools written in interpreted languages.

The tool demonstrates common techniques used in network analysis and security testing within industrial control system (ICS) environments.

## Core Features

*   **ARP Spoofing:** Intercepts communication between the PLC and HMI by poisoning their ARP caches, redirecting traffic through the attacker's machine.
*   **Packet Interception & Modification:** Utilizes NetfilterQueue (`libnetfilter_queue`) on Linux to capture forwarded packets and PcapPlusPlus for parsing and modifying these packets.
*   **Targeted Modbus Manipulation:**
    *   Modifies **Function Code 5 (Write Single Coil)** requests from HMI to PLC and corresponding responses from PLC to HMI by toggling the coil's value (ON to OFF, OFF to ON).
    *   Modifies **Function Code 16 (Write Multiple Registers)** requests from HMI to PLC by randomizing the register values being written. Responses to FC16 are logged but not altered.
*   **PLC IP Discovery:** Can optionally scan the local subnet for PLCs by looking for devices responding on TCP port 502 if a specific PLC IP is not provided.
*   **Command-Line Configuration:** Allows specification of network interface, HMI IP, and PLC IP via command-line arguments.

## Dependencies

To build and run this tool, you will need the following:

*   **PcapPlusPlus:** A C++ library for packet sniffing, crafting, and analysis.
    *   This also has its own dependencies, typically including `libpcap-dev` (or `WinPcap`/`Npcap` on Windows, though this tool is primarily Linux-focused due to NetfilterQueue).
*   **libnetfilter-queue-dev:** Library for userspace handling of packets queued by the kernel's nfqueue mechanism (Linux-specific).
*   **libmnl-dev:** Minimalistic Netlink library, often a dependency for libnetfilter-queue.
*   **CMake:** Version 3.10 or higher, for building the project.
*   **C++17 Compiler:** A C++ compiler that supports C++17 (e.g., g++).
*   **Standard Build Tools:** `make`.

On a Debian/Ubuntu system, you can install most dependencies with:
```bash
sudo apt-get update
sudo apt-get install -y cmake g++ make libpcap-dev libnetfilter-queue-dev libmnl-dev
```
PcapPlusPlus might require manual installation from source if not available in your distribution's repositories or if a specific version is needed. Please refer to the [PcapPlusPlus installation guide](https://pcapplusplus.github.io/docs/install).

## Building

1.  Clone the repository (if applicable) or ensure you have the `main.cpp` and `CMakeLists.txt` files.
2.  Create a build directory and navigate into it:
    ```bash
    mkdir build
    cd build
    ```
3.  Run CMake to configure the project:
    ```bash
    cmake ..
    ```
    *   If PcapPlusPlus is installed in a non-standard location, you might need to help CMake find it, e.g., by setting `PcapPlusPlus_DIR` or modifying `CMAKE_PREFIX_PATH`. The `CMakeLists.txt` includes some common paths.
4.  Compile the project:
    ```bash
    make
    ```
    The executable `mitm_tool` will be created in the `build` directory.

## Running the Tool

**Root privileges are required** for ARP spoofing, raw socket operations, and interacting with NetfilterQueue.

### Getting Help

To see all available command-line options:
```bash
sudo ./build/mitm_tool --help
```
This will typically display:
```
Modbus MITM Tool
------------------
A tool to perform ARP spoofing and manipulate Modbus TCP traffic between an HMI and a PLC.

Usage: sudo ./mitm_tool -i <interface> [-h <hmi_ip>] [-p <plc_ip>]

Options:
  -i, --interface <name|ip> : Network interface to use (e.g., eth0 or 192.168.1.10).
  -h, --hmi-ip <ip_address>   : IP address of the HMI. If not provided, a placeholder is used.
                              (e.g., 192.168.1.101)
  -p, --plc-ip <ip_address>   : IP address of the PLC. If not provided, the tool will scan
                              the local subnet for devices on TCP port 502 and use the first one found.
                              (e.g., 192.168.1.102)
  --help                      : Print this help message and exit.

Example:
  sudo ./mitm_tool -i eth0 -h 192.168.1.101 -p 192.168.1.102
  sudo ./mitm_tool -i eth0 --hmi-ip 192.168.1.101

Note: Root privileges are required for ARP spoofing and network packet operations.
```

### Example Command

```bash
sudo ./build/mitm_tool -i eth0 --hmi-ip 192.168.1.20 --plc-ip 192.168.1.10
```
Replace `eth0`, `192.168.1.20`, and `192.168.1.10` with your actual network interface, HMI IP, and PLC IP respectively.

## Required Environment & Setup

*   **Operating System:** Linux (due to NetfilterQueue and `iptables` usage).
*   **Network Position:** The machine running this tool must be on the same Layer 2 network segment as the target PLC and HMI to effectively perform ARP spoofing.
*   **IP Forwarding:** The tool requires `net.ipv4.ip_forward=1` to be enabled on the attacker machine so that it can forward packets between the HMI and PLC after intercepting them. The tool attempts to enable this setting automatically using `sudo sysctl -w net.ipv4.ip_forward=1`. If this fails, you may need to enable it manually.
*   **Typical Setup:**
    1.  A PLC device configured with an IP address.
    2.  An HMI device (or software) configured to communicate with the PLC's IP address.
    3.  The attacker machine on the same network, running this `mitm_tool`.

## Disclaimer

This tool is provided for educational and research purposes only. Users are solely responsible for their actions and must ensure they have explicit, authorized permission to test on any network or device. Unauthorized use against networks or devices is illegal. The developers assume no liability and are not responsible for any misuse or damage caused by this program.
