import socket
import threading
import time
import os
import nmap

hostname = socket.gethostname()
ip_addr = (
    [
        ip
        for ip in socket.gethostbyname_ex(socket.gethostname())[2]
        if not ip.startswith("127.")
    ]
    or [
        [
            (s.connect(("8.8.8.8", 53)), s.getsockname()[0], s.close())
            for s in [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]
        ][0][1]
    ]
) + ["no IP found"]
print(ip_addr)
devices = []
index = int(input("Enter index of the IP address you want to use: "))
ip = ip_addr[index]

if "no ip found" in ip:
    print("ERROR! Please configure a proper ipv4 address or connect to a network! ")
    exit(1)

print("Your Computer Name is:" + hostname)
print("Your Computer IP Address is:" + ip)
port = 5001
greet = 5002


def perform_handshake(socket, mode):
    socket.send(mode.encode())


def receive_handshake(socket):
    mode = socket.recv(1024).decode()
    return mode


def send_file(socket, file_path):
    file_name = file_path.split("/")[-1]
    file_size = os.path.getsize(file_path)
    perform_handshake(socket, f"send {file_name}")
    fi = open(file_path, "rb")
    sent = 0
    data = fi.read(16384)
    sent += len(data)
    while data:
        socket.send(data)
        data = fi.read(16384)
        sent += len(data)
        print(f"Sent {sent/(1024*1024)}/{file_size/(1024*1024)} MB", end="\r")
    print(f"Sent {sent/(1024*1024)}/{file_size/(1024*1024)} MB")
    fi.close()
    socket.close()


def start_client(dest_ip):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((dest_ip, port))
    print("Connected to server")
    return client_socket


def ping_client(dest_ip):
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((dest_ip, greet))
        devices.append(dest_ip)
        perform_handshake(client_socket, "ping")
        client_socket.close()
    except:
        pass


def run_scan():
    subnet = ".".join(ip.split(".")[:3])
    for i in range(1, 256):
        threading.Thread(target=ping_client, args=(str(subnet + "." + str(i)),)).start()


while True:
    a = input("Do you want to scan for devices? (Y/e): ")
    if a == "e":
        break

    run_scan()
    time.sleep(5)
    devices = list(set(devices))
    for i, j in enumerate(devices):
        print(i, j)
    index = int(input("Choose the device you want to connect to: "))
    dest_ip = devices[index]
    client_socket = start_client(dest_ip)
    print("Do you want to send a file? (yes/no): ")
    user_input = input().lower()
    if user_input == "yes":
        file_path = input("Enter the file path: ")
        file_name = file_path.split("/")[-1]
        file_size = os.path.getsize(file_path)
        perform_handshake(
            client_socket, f"receive {hostname} {file_name} {file_size/(1024*1024)}"
        )
        file_transfer_rejected = False
        while True:
            time.sleep(0.1)
            handshake_mode = receive_handshake(client_socket)

            if handshake_mode == "send":
                send_file(client_socket, file_path)
                break
            elif handshake_mode == "reject":
                file_transfer_rejected = True
                print("File transfer request rejected.\n")
                break
            else:
                print("Waiting for the other device to respond...")

        if not file_transfer_rejected:
            print("File sent successfully.\n")

    else:
        print("File transfer request rejected.\n")
