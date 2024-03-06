import socket
import threading
import time
import os
import ip_util
from ip_util import data, control, greet, chunksize
from handshakes import receive_handshake, perform_handshake

ip_addr, hostname = ip_util.get_ip()
ip = ip_util.choose_ip(ip_addr, hostname)

devices = []


def send_file(socket, file_path):
    file_name = file_path.split("/")[-1]
    file_size = os.path.getsize(file_path)
    fi = open(file_path, "rb")
    sent = 0
    data = fi.read(chunksize)
    sent += len(data)
    while data:
        socket.send(data)
        data = fi.read(chunksize)
        sent += len(data)
        print(f"Sent {sent/(1024*1024)}/{file_size/(1024*1024)} MB", end="\r")
    print(f"Sent {sent/(1024*1024)}/{file_size/(1024*1024)} MB")
    fi.close()
    socket.close()
    print("File sent successfully!")


def start_client(dest_ip):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((dest_ip, data))
    print("Connected to server")
    return client_socket


def ping_client(dest_ip):
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((dest_ip, greet))
        perform_handshake(client_socket, "ping")
        mode = receive_handshake(client_socket)
        if mode.startswith("ping"):
            devices.append(dest_ip)
        client_socket.close()
    except:
        pass


def run_scan():
    subnet = ".".join(ip.split(".")[:3])
    for i in range(1, 256):
        threading.Thread(target=ping_client, args=(str(subnet + "." + str(i)),)).start()


if __name__ == "__main__":
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

        else:
            print("File transfer request rejected.\n")
