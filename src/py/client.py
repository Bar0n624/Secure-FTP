import socket
import threading
import time
import os
import ip_util
from ip_util import data, control, greet, chunksize
from handshakes import (
    receive_handshake,
    perform_handshake,
    send_pub_key,
    send_session_key,
    send_hash,
)
import crypto_utils as cu

devices = []


# def send_file(socket, file_path):
#     file_name = file_path.split("/")[-1]
#     file_size = os.path.getsize(file_path)
#     fi = open(file_path, "rb")
#     sent = 0
#     data = fi.read(chunksize)
#     sent += len(data)
#     while data:
#         socket.send(data)
#         data = fi.read(chunksize)
#         sent += len(data)
#         print(f"Sent {sent/(1024*1024)}/{file_size/(1024*1024)} MB", end="\r")
#     print(f"Sent {sent/(1024*1024)}/{file_size/(1024*1024)} MB")
#     fi.close()
#     socket.close()
#     print("File sent successfully!")


def send_file(socket, file_path, session_key):
    encr = cu.encryptSingleChunk(session_key, file_path, chunksize)
    sent = 0
    for chunk in encr:
        socket.send(chunk)
        sent += len(chunk)
        print(f"Sent {sent/(1024*1024)}/{file_size/(1024*1024)} MB", end="\r")
    print(f"Sent {sent/(1024*1024)}/{file_size/(1024*1024)} MB")
    socket.close()
    os.remove("../../keys/pubserver.pem")
    print("File sent successfully!")


def start_client(dest_ip, port):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((dest_ip, port))
    print("Connected to server")
    return client_socket


def ping_client(dest_ip):
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.settimeout(1)
        client_socket.connect((dest_ip, greet))
        perform_handshake(client_socket, "ping")
        mode = receive_handshake(client_socket)
        if not mode.startswith("reject"):
            devices.append((dest_ip, mode))
        client_socket.close()
    except:
        pass


def run_scan(iprange):
    global devices
    while len(devices) > 0:
        devices.pop()
    threads = [threading.Thread(target=ping_client, args=(i,)) for i in iprange]
    for i in threads:
        i.start()
    for i in threads:
        i.join()


if __name__ == "__main__":
    ip_addr, hostname = ip_util.get_ip()
    ip = ip_util.choose_ip(ip_addr, hostname)
    iprange = ip_util.get_ip_range(ip)

    while True:
        a = input("Do you want to scan for devices? (Y/E): ")
        if a == "E":
            exit(0)

        run_scan(iprange)
        devices = list(set(devices))
        for i, j in enumerate(devices):
            print(i, j)
        index = int(input("Choose the device you want to connect to: "))
        dest_ip = devices[index][0]
        client_socket = start_client(dest_ip, control)
        print("Do you want to send a file? (yes/no): ")
        user_input = input().lower()
        if user_input == "yes":
            file_path = input("Enter the file path: ")
            file_name = file_path.split("/")[-1]
            file_size = os.path.getsize(file_path)
            perform_handshake(
                client_socket, f"receive {hostname} {file_name} {file_size/(1024*1024)}"
            )
            send_pub_key(client_socket)
            pub = client_socket.recv(1024)
            with open("../../keys/pubserver.pem", "wb") as f:
                f.write(pub)
            public_key = "../../keys/pubserver.pem"
            session_key = send_session_key(client_socket, public_key)
            send_hash(client_socket, file_path, public_key)
            while True:
                time.sleep(0.1)
                handshake_mode = receive_handshake(client_socket, True)
                if handshake_mode == "send":
                    data_socket = start_client(dest_ip, data)
                    client_socket.close()
                    send_file(data_socket, file_path, session_key)
                    break
                elif handshake_mode == "reject":
                    print("File transfer request rejected.\n")
                    break
                else:
                    print("Waiting for the other device to respond...")

        else:
            print("File transfer request rejected.\n")
