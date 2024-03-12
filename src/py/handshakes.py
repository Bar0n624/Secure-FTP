import socket, os
import crypto_utils as cu
import rsa_utils as ru

KEYS_DIR = "../../keys/"
CUR_DIR = os.path.abspath(os.path.dirname(__file__))


def perform_handshake(sock, data, pubkey=None):
    if not pubkey:
        sock.send(data.encode())
    else:
        if type(data) == str:
            data = data.encode()
        data = ru.encryptRsa(data, pubkey)
        sock.send(data)


def receive_session_key(sock, privkey):
    data = sock.recv(1024)
    data = ru.decryptRsa(ru.master, data, None)
    return data


def receive_handshake(sock, privkey=None):
    data = sock.recv(1024)
    if not privkey:
        return data.decode()
    # TODO set master key from user interface
    data = ru.decryptRsa(ru.master, data, None)
    # TODO return raw bytes instead of string
    return data.decode()


def send_pub_key(sock):
    public_key_path = os.path.join(CUR_DIR, KEYS_DIR) + "public.pem"
    with open(public_key_path, "rb") as f:
        perform_handshake(sock, f.read().decode())


def send_session_key(sock, encode):
    session_key = cu.getSessionKey()
    perform_handshake(sock, session_key, encode)
    print("Session key sent", session_key)
    return session_key


def create_socket(ip, port):
    socket_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socket_sock.setblocking(False)
    socket_sock.settimeout(5)
    socket_sock.bind((ip, port))
    return socket_sock
