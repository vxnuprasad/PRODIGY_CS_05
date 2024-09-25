import sys
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP

# Banner for the program
banner = """
███╗░░██╗███████╗████████╗░█████╗░██╗░░░░░██╗░░░██╗███████╗███████╗██████╗░
████╗░██║██╔════╝╚══██╔══╝██╔══██╗██║░░░░░╚██╗░██╔╝╚════██║██╔════╝██╔══██╗
██╔██╗██║█████╗░░░░░██║░░░███████║██║░░░░░░╚████╔╝░░░███╔═╝█████╗░░██████╔╝
██║╚████║██╔══╝░░░░░██║░░░██╔══██║██║░░░░░░░╚██╔╝░░██╔══╝░░██╔══╝░░██╔══██╗
██║░╚███║███████╗░░░██║░░░██║░░██║███████╗░░░██║░░░███████╗███████╗██║░░██║
╚═╝░░╚══╝╚══════╝░░░╚═╝░░░╚═╝░░╚═╝╚══════╝░░░╚═╝░░░╚══════╝╚══════╝╚═╝░░╚═╝
"""
print(banner)
print("--------------- Network Packet Analyzer By Techno-rabit ---------------\n")

print("-------------------------------- Disclaimer --------------------------------\n")
print("This packet sniffer tool is intended for educational and ethical purposes only.\n")
print("By using this tool, you agree to the following terms and conditions:\n")
print("\n1. You will only use this tool on networks and systems for which you have explicit permission.")
print("2. You will not use this tool to violate any laws, regulations, or terms of service.")
print("3. You will not use this tool to harm, disrupt, or exploit any networks or systems.")
print("4. You will not use this tool to intercept, collect, or store any sensitive or confidential information.")
print("5. You will not redistribute or sell this tool without the express permission of the author.")
print("6. The author is not responsible for any damages or losses incurred as a result of using this tool.")
print("7. You will respect the privacy and security of all networks and systems you interact with using this tool.")

accept_terms = input("\nDo you accept these terms and conditions? (y/n): ")

if accept_terms.lower() != 'y':
    print("You must accept the terms and conditions before using this tool.")
    sys.exit()

# Function to handle packet processing
def packet_callback(packet):
    # Check if the packet has an IP layer
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = None
        
        # Determine the protocol type (TCP, UDP, ICMP)
        if packet.haslayer(TCP):
            protocol = "TCP"
        elif packet.haslayer(UDP):
            protocol = "UDP"
        elif packet.haslayer(ICMP):
            protocol = "ICMP"
        else:
            protocol = "Other"

        # Print source, destination, and protocol
        print(f"Source IP: {ip_src}, Destination IP: {ip_dst}, Protocol: {protocol}")
        
        # Display payload data if the packet has a TCP or UDP layer
        if packet.haslayer(TCP) or packet.haslayer(UDP):
            print(f"Payload: {bytes(packet[protocol].payload)}\n")
        else:
            print(f"No TCP/UDP payload available.\n")

# Function to start packet sniffing on a given interface
def start_sniffing(interface="eth0", count=10):
    print(f"Starting packet capture on {interface}...")
    sniff(iface=interface, prn=packet_callback, count=count)

# Main logic
if __name__ == "__main__":
    # Prompt the user to enter the network interface
    network_interface = input("Enter the network interface to sniff on (e.g., eth0, wlan0): ")
    
    # Start packet sniffing
    start_sniffing(interface=network_interface, count=10)  # Adjust count as needed
