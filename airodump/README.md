## Overview

This is a simple wireless network sniffer tool designed for educational and research purposes. The program captures 802.11 beacon and data frames using raw sockets on Linux. It extracts essential information such as the BSSID (MAC address), ESSID (network name), signal strength (RSSI), and frame counts, while automatically hopping through channels to monitor multiple wireless networks.

https://gitlab.com/gilgil/sns/-/wikis/dot11-frame/report-airodump

## Core Concepts

- **Raw Sockets & Monitor Mode:**

https://gitlab.com/gilgil/sns/-/wikis/monitor-mode/monitor-mode
    
    Utilizes Linux AF_PACKET raw sockets (`socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))`) to capture all data link layer packets directly. The wireless interface must be set to monitor mode (using ifconfig/iwconfig/airmon-ng) to capture all wireless frames (management, control, and data).
    
- **Radiotap Header:**
    
    Each captured packet is prefixed with a Radiotap header which contains meta-information like signal strength (RSSI), channel, and other parameters.
    
- **802.11 Beacon Frames:**
    
    These management frames are transmitted periodically by access points (APs) to announce network presence. The tool parses beacon frames to extract the AP’s BSSID and ESSID along with other relevant information.
    
- **Channel Hopping:**
    
    A dedicated thread cycles through different channels using system commands (e.g., `iw dev <interface> set channel <n>`) to ensure that packets from APs on various channels are captured.
    

## How It Works

1. **Initialization:**
    
    The program accepts command-line options to set the wireless interface, channel hopping interval, and maximum channel number. It then creates and binds a raw socket to capture all network packets.
    
2. **Packet Capture and Parsing:**
    
    Captured packets are processed to:
    
    - Parse the Radiotap header for RSSI.
    - Determine the packet type (beacon or data).
    - Extract beacon frame details (BSSID, ESSID) and update the access point list.
    - For data frames, parse the header to extract the corresponding BSSID and update data frame counts.
3. **Channel Hopping:**
    
    A separate thread changes the interface channel periodically, ensuring a comprehensive scan over a range of channels.
    
4. **Display:**
    
    The AP list, along with the captured details, is refreshed in real time on the console.
    

## Usage

Run the tool with the following command:

```bash

sudo ./airodump -i <interface> [-t hop_interval] [-m max_channel]

```

Example:

```bash

sudo ./airodump -i mon0 -t 1 -m 14

```

**Note:** This program is intended for use in environments where you have explicit permission to capture wireless traffic. Unauthorized monitoring or interception of wireless data may be illegal.
