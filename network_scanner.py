import scapy.all as scapy
import argparse

def get_arguments():
    parser = argparse.ArgumentParser(description="Network Scanner using ARP")
    parser.add_argument("-t", "--target", dest="network_ip", required=True, help="Target IP / IP range to scan")
    args = parser.parse_args()
    return args

def scan(network_ip):
    try:
        arp_request = scapy.ARP(pdst=network_ip)
        arp_broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = arp_broadcast / arp_request
        answered = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
        client_list = []

        for ans in answered:
            client_dict = {"ip": ans[1].psrc, "mac": ans[1].hwsrc}
            client_list.append(client_dict)

        return client_list
    except Exception as e:
        print(f"Error occurred during scanning: {e}")
        return []

def display_clients(clients):
    if clients:
        print("IP Address\t\tMAC Address")
        print("-" * 42)
        for client in clients:
            print(client["ip"], "\t\t", client["mac"])
    else:
        print("No clients found.")

if __name__ == "__main__":
    options = get_arguments()
    client_list = scan(options.network_ip)
    display_clients(client_list)
