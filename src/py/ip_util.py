import socket
import netifaces
import ipaddress

DATA_PORT = 5001
CONTROL_PORT = 5002
GREET_PORT = 5003
CHUNK_SIZE = 4096


def get_ip():
    hostname = socket.gethostname()
    ip_list = []
    for interface in netifaces.interfaces():
        try:
            for link in netifaces.ifaddresses(interface)[netifaces.AF_INET]:
                ip_list.append(link["addr"]) if not link["addr"].startswith(
                    "127.0"
                ) else None
        except KeyError:
            pass
    return ip_list, hostname


def get_ip_range(ip):
    # function returns all the ip addresses in the same network as the given ip address
    ip_range = ""
    network = netifaces.interfaces()
    for i in network:
        addr = netifaces.ifaddresses(i)
        if netifaces.AF_INET in addr:
            addr = addr[netifaces.AF_INET]
        else:
            continue
        for j in addr:
            if j["addr"] == ip:
                ip_range = j["addr"] + "/" + j["netmask"]
                break
    ips = [str(ip) for ip in ipaddress.IPv4Network(ip_range, strict=False)]
    return ips


def choose_ip(ip_addr, hostname):
    if len(ip_addr) == 1:
        ip = ip_addr[0]
    elif len(ip_addr) > 1:
        print(ip_addr)
        index = int(input("Enter index of the IP address you want to use: "))
        ip = ip_addr[index]
    else:
        print("Error: No IP Address found.")
        exit(1)
    print("Your Computer Name is:" + hostname)
    print("Your Computer IP Address is:" + ip)
    return ip
