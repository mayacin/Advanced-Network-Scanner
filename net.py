import scapy.all as scapy
import nmap
import socket


def scan_network(ip_range):
    print("[+] Scanning network for active devices...")
    arp_request = scapy.ARP(pdst=ip_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    devices = []
    for element in answered_list:
        devices.append({"ip": element[1].psrc, "mac": element[1].hwsrc})

    return devices


def scan_ports(target_ip):
    print(f"[+] Scanning ports on {target_ip}...")
    scanner = nmap.PortScanner()
    scanner.scan(target_ip, '1-65535', '-sV')

    scan_results = []
    for proto in scanner[target_ip].all_protocols():
        ports = scanner[target_ip][proto].keys()
        for port in ports:
            service = scanner[target_ip][proto][port]['name']
            scan_results.append((port, service))

    return scan_results


def detect_os(target_ip):
    print(f"[+] Detecting OS on {target_ip}...")
    scanner = nmap.PortScanner()
    scanner.scan(target_ip, arguments='-O')
    try:
        os_match = scanner[target_ip]['osmatch'][0]['name']
    except (KeyError, IndexError):
        os_match = "Unknown"
    return os_match


def get_host_info(ip):
    try:
        hostname = socket.gethostbyaddr(ip)[0]
    except socket.herror:
        hostname = "Unknown"
    return hostname


def main():
    ip_range = input("Enter IP range to scan (e.g., 192.168.1.0/24): ")
    devices = scan_network(ip_range)

    if not devices:
        print("No active devices found.")
        return

    print("\nActive Devices:")
    for idx, device in enumerate(devices, 1):
        print(f"{idx}. IP: {device['ip']} - MAC: {device['mac']}")

    target_ip = input("Enter target IP for detailed scanning: ")
    ports = scan_ports(target_ip)
    os_detected = detect_os(target_ip)
    hostname = get_host_info(target_ip)

    print(f"\n[+] Hostname: {hostname}")
    print(f"[+] OS Detected: {os_detected}")
    print("[+] Open Ports:")
    for port, service in ports:
        print(f"  - {port}: {service}")


if __name__ == "__main__":
    main()

