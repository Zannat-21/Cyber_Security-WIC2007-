import argparse
from scapy.all import IP, TCP, sr

def port_scan(target_ip, ports, timeout=2):
    open_ports = []
    for port in ports:
        # Craft TCP SYN packet
        syn_packet = IP(dst=target_ip) / TCP(dport=port, flags="S")

        # Send packet and capture response
        response = sr(syn_packet, timeout=timeout, verbose=False)[0]

        # Check if port is open based on response
        if response and response[0][1][TCP].flags == 18:  # SYN-ACK
            open_ports.append(port)

    return open_ports

if __name__ == "__main__":
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="Port scanning tool using Scapy")
    parser.add_argument("target_ip", help="Target IP address to scan")
    parser.add_argument("--ports", nargs="+", type=int, help="List of ports to scan", default=range(1, 1025))
    args = parser.parse_args()

    # Perform port scanning
    open_ports = port_scan(args.target_ip, args.ports)

    # Print open ports
    if open_ports:
        print("Open ports:", open_ports)
    else:
        print("No open ports found.")
