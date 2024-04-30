# BeaconSniffer
A tool developed for a university project. 

# What is BeaconSniffer
BeaconSniffer is a tool that was designed to detect and prevent Karma attacks in 802.11 networks for a university project.

It works by performing extraction and analysis on an access point's beacon frames to generate a unique hardware signature that can be stored for reference.

If an SSID with the same name is observed, the tool can check to see if the signature (and therefore, likely the hardware\) matches. If it is different, it could be a spoofed access point

An SSID can have multiple 'trusted' signatures due to AP roaming and dual-band access points


# How to Use the WiFi Beacon Sniffer Tool

This guide will walk you through using the WiFi Beacon Sniffer tool, a Python-based program designed to detect and analyze beacon frames from wireless networks. This tool is useful for identifying rogue access points that could be used for malicious purposes, such as KARMA attacks.

## Requirements

- **Python**: Ensure you have Python installed on your system.
- **Scapy**: This tool uses the Scapy library for packet manipulation and sniffing. Install it using pip.
- **Wireless Interface**: A wireless interface capable of monitor mode is required.
- **Linux-Based System**: The tool uses Linux-specific commands (`ifconfig`, `iwconfig`, `nmcli`), so it's best suited for Linux environments.

## Getting Started

1. **Download the Tool**: Clone or download the project's files to your local machine.
2. **Set Up**: Navigate to the project directory in your terminal.
3. **Choose Your Wireless Interface**: Identify the wireless interface you wish to use. You can list all available interfaces with the command `ifconfig` or `ip a`.
4. **Install Scapy if required**: `pip install Scapy`

## Running the Tool

To start using the tool, you will need to run `Project.py` with Python. Here’s how to use the command-line options to customize your sniffing session:

- **Interface**: Specify the wireless interface for sniffing.
- **Channel**: (Optional `-c <channel>`) Define the channel to listen to. The default is channel 1.
- **Output**: (Optional `–o <count>`) Set how many packets you want to save to a pcap file for debugging purposes. The default is 0 (no output).
- **Sniff**: (Optional `-s <ssid>`) Provide the SSID of a trusted network to save a signature for. This helps in detecting any duplicate signatures for trusted SSIDs.
- **Prevention**: (Optional `-p <True>`) Enable prevention functionality to remove suspicious SSIDs from the Preferred Network List (PNL). Default is disabled.

### Example Command

```bash
python Project.py -i wlan0 -c 6 -o 100 -s "MyHomeNetwork" -p True
```

This command configures the tool to sniff on interface `wlan0`, listening on channel 6, saving up to 100 packets to a pcap file, focusing on the SSID "MyHomeNetwork" for signature saving, and enabling the prevention feature. 
