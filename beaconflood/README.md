# Beacon Flooding Attack Tool

## Overview

This tool generates and continuously sends fake 802.11 beacon frames to simulate multiple wireless access points (APs) using a list of SSIDs. Its main purpose is for stress testing and research on wireless networks. **Note:** Use this tool only in environments where you have explicit permission.

https://gitlab.com/gilgil/g/-/blob/master/src/net/process/gbeaconflood.cpp

https://kalilinuxtutorials.com/mdk3/


## Basic Concepts

- **Beacon Frames:**
    
    Beacon frames are management frames that real APs broadcast periodically to announce network presence and settings (SSID, BSSID, supported rates, etc.). This tool mimics these frames with fake data.
    
- **Raw Sockets:**
    
    The code uses Linux raw sockets (via `socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))`) to send packets directly at the data link layer.
    
- **Monitor Mode:**
    
    The wireless interface must be set to monitor mode to capture and transmit all wireless frames, even those not meant for the host device.
    
- **Channel Hopping:**
    
    The tool implements channel hopping. It periodically changes the wireless channel so that the beacon frames are transmitted across different channels.
    

## Code Structure and Operation

1. **Signal Handling:**
    
    A SIGINT (Ctrl+C) handler is set up to allow graceful termination of the flooding process.
    
2. **SSID List and MAC Generation:**
    - The tool reads SSIDs from a provided file (one SSID per line).
    - For each SSID, a random (but locally administered) BSSID is generated.
3. **Beacon Frame Construction:**
    
    The `build_beacon_frame()` function assembles the following components in order:
    
    - **Radiotap Header:** A simple header to include wireless metadata.
    - **802.11 Beacon Header:** This contains frame control, addresses (with BSSID), duration, and sequence control.
    - **Fixed Parameters:** Such as timestamp, beacon interval, and capabilities.
    - **Information Elements (IEs):**
        - SSID Tag: Contains the network name.
        - Supported Rates and Extended Supported Rates Tags.
        - DS Parameter Set Tag: Contains the current channel number.
4. **Channel Hopping:**
    
    A separate thread runs the `channel_hopper()` function. This periodically sets the interface to a new channel using the system command (`iw dev <interface> set channel <n>`).
    
5. **Beacon Flooding Loop:**
    
    The main loop builds a beacon frame for each SSID using the current channel and sends it repeatedly via a raw socket. A very short delay is used between each send to achieve a high transmission rate.
    

## Purpose

- **Stress Testing:**
    
    Evaluate how wireless network tools or devices handle large numbers of beacon frames.
    
- **Security Research:**
    
    Demonstrate vulnerabilities in network scanners or drivers when bombarded with fake APs.
    
- **Educational Use:**
    
    Learn how wireless beacon frames are structured and how wireless network attacks can be implemented.
    

## Usage

### Prerequisites

- A Linux system with a wireless adapter that supports monitor mode.
- The wireless interface must be switched to monitor mode (use tools like `airmon-ng`).
- You must have root privileges.

### Compilation

Compile the code with the following command:

```bash
gcc -o mdk_s mdk_s.c -lpthread

```

### Execution

Run the tool with:

```bash
sudo ./mdk_s <interface> <ssid_list_file>

```

**Example:**

```bash
sudo ./mdk_s mon0 ssid-list.txt

```

In this example, `mon0` is the monitor mode interface, and `ssid-list.txt` is a text file containing SSIDs (one per line) that will be used to create the fake APs.

## Disclaimer

This tool is provided for educational and research purposes only. Do not use it on networks without explicit permission, as unauthorized use is illegal and unethical.
