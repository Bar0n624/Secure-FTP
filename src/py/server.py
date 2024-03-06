import socket
import threading
import time
import os

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


def receive_file(socket, size):
    handshake_info = receive_handshake(socket)
    _, file_name = handshake_info.split(" ", 1)
    with open(f"../../files/{file_name}", "wb") as file:
        received = 16384
        data = socket.recv(16384)
        while data:
            file.write(data)
            data = socket.recv(16384)
            received += 16384
            if received >= float(size) * 1024 * 1024:
                received = float(size) * 1024 * 1024
            print(f"Received {received/(1024*1024)}/{size} MB", end="\r")
    print(f"Received {received/(1024*1024)}/{size} MB")
    print(f"File '{file_name}' received successfully")


def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    greet_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    greet_socket.bind((ip, greet))
    server_socket.bind((ip, port))
    server_socket.listen()
    greet_socket.listen()
    print(f"Server listening on socket {ip}:{port}...")

    while True:
        conn, addr = greet_socket.accept()
        conn, addr = server_socket.accept()
        threading.Thread(target=handle_client, args=(conn, addr)).start()


def handle_client(conn, addr):
    handshake_mode = receive_handshake(conn)

    if handshake_mode.startswith("receive"):
        print(f"Connection established with {addr} {handshake_mode.split(' ')[1]}")
        print(
            f"Incoming file {handshake_mode.split(' ')[2]} {handshake_mode.split(' ')[3]}MB transfer request. Do you want to accept? (yes/no): "
        )
        user_input = input().lower()

        if user_input == "yes":
            perform_handshake(conn, "send")
            receive_file(conn, handshake_mode.split(" ")[3])
        else:
            perform_handshake(conn, "reject")


start_server()
