import threading
import time
import getpass
import os
import ip_util
from ip_util import DATA_PORT, CONTROL_PORT, GREET_PORT, CHUNK_SIZE
from handshakes import (
    perform_handshake,
    receive_handshake,
    create_socket,
    send_pub_key,
    receive_session_key,
    receive_file_digest,
)
import select
import crypto_utils as cu
from colors import *

# Global control flags
busy_flag = 0
connection = 0


def handle_receive(conn, addr, handshake_mode, data_socket, hostname):
    global busy_flag, connection

    if busy_flag:
        perform_handshake(conn, "reject")
        return

    connection = 1

    print(f"[ALERT] {FG_GREEN_LIGHT}Connection established{FG_BG_CLEAR} "
          f"with {FG_BLUE}{hostname}{FG_BG_CLEAR} @ {FG_BLUE}{addr[0]}{FG_BG_CLEAR}", end="\n\n")

    # XXX
    while True:
        pub = conn.recv(1024)
        time.sleep(0.1)
        if pub:
            break

    with open("../../keys/pubclient.pem", 'wb') as f:
        f.write(pub)

    public_key = "pubclient.pem"
    send_pub_key(conn)
    session_key = receive_session_key(conn)
    digest = receive_file_digest(conn, True)

    print("[ALERT] Incoming file "
          f"{FG_BLUE}{handshake_mode.split(' ')[2]}{FG_BG_CLEAR} "
          f"of size {FG_BLUE}{round(float(handshake_mode.split(' ')[3]), 3)} MB{FG_BG_CLEAR}\n"
          "Accept file transfer? (yes/no): ", end="")

    if input().lower() == "yes":
        busy_flag = 1
        perform_handshake(conn, "send", public_key)
        data_socket.setblocking(True)
        conn, addr = data_socket.accept()
        receive_file(
            conn,
            handshake_mode.split(" ")[2],
            handshake_mode.split(" ")[3],
            session_key,
            digest
        )
    else:
        perform_handshake(conn, "reject")
        connection = 0


def handle_ping(conn, addr, hostname):
    print(
        f"[ALERT] {FG_YELLOW}Ping{FG_BG_CLEAR} from {FG_BLUE}{hostname}{FG_BG_CLEAR} @ "
        f"{FG_BLUE}{addr[0]}{FG_BG_CLEAR}", end="\n\n")

    if busy_flag:
        perform_handshake(conn, "reject")
    else:
        perform_handshake(conn, hostname)


def handle_client(conn, addr, data_socket, hostname):
    handshake_mode = receive_handshake(conn)

    if handshake_mode.startswith("receive"):
        handle_receive(conn, addr, handshake_mode, data_socket, hostname)
    elif handshake_mode.startswith("ping"):
        handle_ping(conn, addr, hostname)


def receive_file(sock, file_name, size, session_key, digest):
    global busy_flag, connection

    file_name = os.path.basename(file_name)
    start_time = time.time()

    print("\n")

    with open(f"../../files/{file_name}.tmp", 'wb') as f:
        received = 0
        data = sock.recv(CHUNK_SIZE)
        while data:
            f.write(data)

            data = sock.recv(CHUNK_SIZE)
            received = os.path.getsize(f"../../files/{file_name}.tmp")
            if received >= float(size) * 1024 * 1024:
                received = float(size) * 1024 * 1024

            # Calculate ETA
            bytes_remaining = float(size) * 1024 * 1024 - received
            elapsed_time = time.time() - start_time
            try:
                transfer_rate = received / elapsed_time
                eta = bytes_remaining / transfer_rate
                eta_formatted = time.strftime("%H:%M:%S", time.gmtime(eta))
                print(f"Received {FG_BLUE}{round(received / (1024 * 1024), 3):7.4f} of {round(float(size), 3):7.4f} MB{FG_BG_CLEAR}  ETA {FG_BLUE}{eta_formatted}{FG_BG_CLEAR}    ", end="\r")
            except ZeroDivisionError:
                print("Calculating ETA...", end="\r")

    print("\r\n\n")
    print("Decrypting file...", end="\n\n")

    cu.decryptFile(
        session_key,
        f"../../files/{file_name}.tmp",
        f"../../files/{file_name}",
        CHUNK_SIZE,
    )
    os.remove(f"../../files/{file_name}.tmp")

    recvhash = cu.calculateFileDigest(f"../../files/{file_name}")
    if recvhash == digest:
        print(
            f"[ALERT] File {FG_BLUE}{file_name}{FG_BG_CLEAR} received {FG_GREEN_LIGHT}successfully{FG_BG_CLEAR}", end="\n\n")
    else:
        print(f"[ALERT] File transfer {FG_RED_LIGHT}failed{FG_BG_CLEAR}")
        os.remove(f"../../files/{file_name}")

    os.remove(f"../../keys/pubclient.pem")
    busy_flag = 0
    connection = 0


def start_server(ip, hostname):
    data_socket = create_socket(ip, DATA_PORT)
    data_socket.listen()

    greet_socket = create_socket(ip, GREET_PORT)
    greet_socket.listen()

    control_socket = create_socket(ip, CONTROL_PORT)
    control_socket.listen()

    socks = [greet_socket, control_socket]

    print(
        f"[ALERT] You are discoverable as {FG_BLUE}{hostname}{FG_BG_CLEAR} @ "
        f"{FG_BLUE}{ip}{FG_BG_CLEAR}", end="\n\n"
    )

    while True:
        readable, _, _ = select.select(socks, [], [])

        for i in readable:
            conn, addr = i.accept()
            threading.Thread(
                target=handle_client, args=(conn, addr, data_socket, hostname)
            ).start()


if __name__ == "__main__":
    while (cu.setMasterKey(getpass.getpass("Master key: ")) != 1):
        print(f"Key is {FG_RED_LIGHT}invalid{FG_BG_CLEAR}", end="\n")
    print(f"Master key {FG_GREEN_LIGHT}validated{FG_BG_CLEAR}", end="\n")
    time.sleep(1)

    if not (os.path.isfile("../../keys/public.pem")\
            and os.path.isfile("../../keys/private.der")):
        cu.generateNewKeypair(public_out="public.pem",
                              private_out="private.der")

    ip_addr, hostname = ip_util.get_ip()
    ip = ip_util.choose_ip(ip_addr)
    start_server(ip, hostname)
