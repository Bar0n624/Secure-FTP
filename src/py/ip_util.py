import socket
import netifaces
import ipaddress

data = 5001
control = 5002
greet = 5003
chunksize = 4096


def get_ip():
    hostname = socket.gethostname()
    ip_addr = [
        ip
        for ip in socket.gethostbyname_ex(socket.gethostname())[2]
        if not ip.startswith("127.")
    ] or [
        [
            (s.connect(("8.8.8.8", 53)), s.getsockname()[0], s.close())
            for s in [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]
        ][0][1]
    ]
    return ip_addr, hostname


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
