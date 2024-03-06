import socket


def perform_handshake(sock, mode):
    sock.send(mode.encode())


def receive_handshake(sock):
    mode = sock.recv(1024).decode()
    return mode


def create_socket(ip, port):
    socket_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socket_sock.setblocking(False)
    socket_sock.settimeout(5)
    socket_sock.bind((ip, port))
    return socket_sock
