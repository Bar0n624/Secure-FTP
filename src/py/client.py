import socket
import threading
import time
import os
from ip_util import (
    DATA_PORT,
    CONTROL_PORT,
    GREET_PORT,
    CHUNK_SIZE,
    choose_ip,
    get_ip,
    get_ip_range,
)
from handshakes import (
    receive_handshake,
    perform_handshake,
    send_pub_key,
    send_session_key,
    send_file_digest,
)
import crypto_utils as cu
from colors import *
import curses
import getpass

devices = []


def send_file(socket, file_path, session_key, file_size, progress_update=None):
    encr = cu.encryptSingleChunk(session_key, file_path, CHUNK_SIZE)
    sent = 0
    start_time = time.time()
    file_size_mb = file_size / (1024 * 1024)
    print("Encrypting and sending file, this may take a while...", end="\n\n")
    for chunk in encr:
        socket.send(chunk)
        sent += len(chunk)
        sent_mb = sent / (1024 * 1024)
        elapsed_time = time.time() - start_time
        try:
            perc = round(sent / file_size, 2)
            transfer_rate = sent / elapsed_time
            eta = (file_size - sent) / transfer_rate
            eta_formatted = time.strftime("%H:%M:%S", time.gmtime(eta))
            speed = sent / (1024 * elapsed_time)
            print(f"{int(perc * 100):3d}% [{f'{FG_GREEN}#{FG_BG_CLEAR}'*int(perc*50)}{f'{FG_RED_LIGHT}.{FG_BG_CLEAR}'*(50 - int(perc*50))}] "
                f"{FG_BLUE}{round(sent_mb, 3):7.4f}/{round(file_size_mb, 3):7.4f} MB{FG_BG_CLEAR} | "
                f"{FG_BLUE}{round(speed, 2):7.2f} KBps{FG_BG_CLEAR} | "
                f"ETA {FG_BLUE}{eta_formatted}{FG_BG_CLEAR}    ",
                end="\r"
                )
        except ZeroDivisionError:
            print("Calculating ETA...", end="\r")

    print("\n")
    socket.close()
    os.remove("../../keys/pubserver.pem")
    print(f"[ALERT] File sent {FG_GREEN}successfully{FG_BG_CLEAR}", end="\n\n")


def start_client(dest_ip, port):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((dest_ip, port))
    print(
        f"[ALERT] {FG_GREEN}Connected{FG_BG_CLEAR} to {FG_BLUE}{dest_ip}{FG_BG_CLEAR}", end="\n\n")
    return client_socket


def ping_client(dest_ip):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(1)  # Set timeout for response
        try:
            s.sendto(b"ping", (dest_ip, GREET_PORT))
            mode, _ = s.recvfrom(1024)
            mode = mode.decode("utf-8")
            if not mode.startswith("reject"):
                devices.append((dest_ip, mode))
        except:
            pass


def run_scan(iprange):
    global devices
    while len(devices) > 0:
        devices.pop()
    threads = [threading.Thread(target=ping_client, args=(i,))
               for i in iprange]
    for i in threads:
        i.start()
    for i in threads:
        i.join()


def handshake(hostname, file_name, file_size, client_socket, file_path, dest_ip):
    perform_handshake(
        client_socket, f"receive {hostname} {file_name} {file_size / (1024 * 1024)}"
    )
    send_pub_key(client_socket)
    pub = client_socket.recv(1024)
    with open("../../keys/pubserver.pem", "wb") as f:
        f.write(pub)

    public_key = "pubserver.pem"
    session_key = send_session_key(client_socket, public_key)
    send_file_digest(client_socket, file_path, public_key)

    while True:
        time.sleep(0.1)
        handshake_mode = receive_handshake(client_socket, True)
        if handshake_mode == "send":
            data_socket = start_client(dest_ip, DATA_PORT)
            client_socket.close()
            send_file(data_socket, file_path, session_key, file_size)
            break
        elif handshake_mode == "reject":
            print(f"[ALERT] File transfer request {FG_RED_LIGHT}rejected{FG_BG_CLEAR}", end="\n\n")
            break

dest_ip = None

def character(stdscr):
    attributes = {}
    curses.init_pair(1, curses.COLOR_WHITE, curses.COLOR_BLACK)
    attributes['normal'] = curses.color_pair(1)

    curses.init_pair(2, curses.COLOR_BLACK, curses.COLOR_WHITE)
    attributes['highlighted'] = curses.color_pair(2)

    c = 0
    option = 0
    while c != 10:
        stdscr.erase()
        stdscr.addstr("Select the device you want to connect to\n",
                      curses.A_UNDERLINE)
        for i in range(len(devices)):
            if i == option:
                attr = attributes['highlighted']
            else:
                attr = attributes['normal']
            stdscr.addstr(str(devices[i][1]) + " @ " +
                          str(devices[i][0]) + "\n", attr)
        c = stdscr.getch()
        if c == curses.KEY_UP and option > 0:
            option -= 1
        elif c == curses.KEY_DOWN and option < len(devices) - 1:
            option += 1

    stdscr.getch()

    global dest_ip
    dest_ip = devices[option][0]


def connect(hostname, ip, iprange):
    global devices
    while True:
        a = input("Scan for devices on the network? (yes/no) ")
        if a.lower() != "yes":
            exit(0)

        run_scan(iprange)
        devices = list(set(devices))
        curses.wrapper(character)

        client_socket = start_client(dest_ip, CONTROL_PORT)

        inp = input(
            f"Send a file to {FG_BLUE}{hostname}{FG_BG_CLEAR} @ {FG_BLUE}{ip}{FG_BG_CLEAR}? (yes/no) ")
        if inp.lower() == "yes":
            file_path = input("\nEnter the complete file path ")
            file_name = os.path.basename(file_path)
            file_size = os.path.getsize(file_path)
            handshake(hostname, file_name, file_size,
                      client_socket, file_path, dest_ip)


if __name__ == "__main__":
    while (cu.setMasterKey(getpass.getpass("Master key ")) != 1):
        print(f"Key is {FG_RED_LIGHT}invalid{FG_BG_CLEAR}")
    print(f"Master key {FG_GREEN_LIGHT}validated{FG_BG_CLEAR}", end="\n\n")
    time.sleep(1)

    if not (
        os.path.isfile("../../keys/public.pem")
        and os.path.isfile("../../keys/private.der")
    ):
        cu.generateNewKeypair(public_out="public.pem",
                              private_out="private.der")

    ip_addr, hostname = get_ip()
    ip = choose_ip(ip_addr)
    iprange = get_ip_range(ip)
    connect(hostname, ip, iprange)
