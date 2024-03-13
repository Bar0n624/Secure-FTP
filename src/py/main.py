# Note all function implementations is done at the end of setupUi function
# The function names are self explanatory and the comments are also there to help you understand the flow

from PyQt5 import QtCore, QtGui, QtWidgets
from server_interface import Ui_serverWindow
import os
import crypto_utils as cu
import ip_util
import threading
from except_thread import thread_with_exception
import socket
import time
from ip_util import DATA_PORT, CONTROL_PORT, GREET_PORT, CHUNK_SIZE, choose_ip, get_ip, get_ip_range
from handshakes import (
    perform_handshake,
    receive_handshake,
    create_socket,
    send_pub_key,
    receive_session_key,
    receive_file_digest,
    send_session_key,
    send_file_digest
)
import select



thread=None
busy_flag = 0
user_input = ''
devices=[]


class Ui_MainWindow(object):

    def send_file(self, socket, file_path, session_key, file_size):
        encr = cu.encryptSingleChunk(session_key, file_path, CHUNK_SIZE)
        sent = 0
        for chunk in encr:
            socket.send(chunk)
            sent += len(chunk)
            print(f"Sent {sent/(1024*1024)}/{file_size/(1024*1024)} MB", end="\r")
        print(f"Sent {sent/(1024*1024)}/{file_size/(1024*1024)} MB")
        socket.close()
        os.remove("../../keys/pubserver.pem")
        print("File sent successfully!")


    def start_client(self, dest_ip, port):
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((dest_ip, port))
        print("Connected to server")
        return client_socket


    def ping_client(self, dest_ip):
        try:
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.settimeout(1)
            client_socket.connect((dest_ip, GREET_PORT))
            perform_handshake(client_socket, "ping")
            mode = receive_handshake(client_socket)
            if not mode.startswith("reject"):
                devices.append((dest_ip, mode))
            client_socket.close()
        except:
            pass


    def run_scan(self, iprange):
        global devices
        while len(devices) > 0:
            devices.pop()
        threads = [threading.Thread(target=self.ping_client, args=(i,)) for i in iprange]
        for i in threads:
            i.start()
        for i in threads:
            i.join()

    def connection(self, dest_ip, file_path, hostname):
        client_socket = self.start_client(dest_ip, CONTROL_PORT)
        file_name = os.path.basename(file_path)
        file_size = os.path.getsize(file_path)
        perform_handshake(
            client_socket, f"receive {hostname} {file_name} {file_size/(1024*1024)}"
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
                data_socket = self.start_client(dest_ip, DATA_PORT)
                client_socket.close()
                self.send_file(data_socket, file_path, session_key, file_size)
                break
            elif handshake_mode == "reject":
                print("File transfer request rejected.\n")
                break
            else:
                print("Waiting for the other device to respond...")

    def handle_receive(self, conn, addr, handshake_mode, data_socket, hostname):
        global busy_flag
        if busy_flag:
            perform_handshake(conn, "reject")
            return
        print(f"Connection established with {addr} {handshake_mode.split(' ')[1]}")
        pub = conn.recv(1024)
        with open("../../keys/pubclient.pem", "wb") as f:
            f.write(pub)
        public_key = "pubclient.pem"
        send_pub_key(conn)
        session_key = receive_session_key(conn)
        print(session_key)
        digest = receive_file_digest(conn, True)
        print(digest)
        global filereceivetext
        filereceivetext=f"Incoming file {handshake_mode.split(' ')[2]} {handshake_mode.split(' ')[3]}MB transfer request. Do you want to accept? (yes/no): "
        self.recieving_file_request_label.setText(filereceivetext)
        print(filereceivetext)
        while user_input=='':
            pass
        if user_input == "yes":
            busy_flag = 1
            perform_handshake(conn, "send", public_key)
            data_socket.setblocking(True)
            conn, addr = data_socket.accept()
            self.receive_file(
                conn,
                handshake_mode.split(" ")[2],
                handshake_mode.split(" ")[3],
                session_key,
                digest,
            )
        else:
            perform_handshake(conn, "reject")
    
    
    def handle_ping(self, conn, hostname):
        print("ping")
        if busy_flag:
            perform_handshake(conn, "reject")
        else:
            perform_handshake(conn, hostname)


    def handle_client(self, conn, addr, data_socket, hostname):
        handshake_mode = receive_handshake(conn)
        if handshake_mode.startswith("receive"):
            self.handle_receive(conn, addr, handshake_mode, data_socket, hostname)
        elif handshake_mode.startswith("ping"):
            self.handle_ping(conn, hostname)


    def receive_file(self, sock, file_name, size, session_key, hash):
        global busy_flag
        file_name = os.path.basename(file_name)
        with open(f"../../files/{file_name}.tmp", "wb") as f:
            received = 0
            data = sock.recv(CHUNK_SIZE)
            while data:
                f.write(data)
                data = sock.recv(CHUNK_SIZE)
                received = os.path.getsize(f"../../files/{file_name}.tmp")
                if received >= float(size) * 1024 * 1024:
                    received = float(size) * 1024 * 1024
                print(f"Received {received/(1024*1024)}/{size} MB", end="\r")
        print(f"Received {received/(1024*1024)}/{size} MB")
        cu.decryptFile(
            session_key,
            f"../../files/{file_name}.tmp",
            f"../../files/{file_name}",
            CHUNK_SIZE,
        )
        os.remove(f"../../files/{file_name}.tmp")
        print("Decrypting file...")
        recvhash = cu.calculateFileDigest(f"../../files/{file_name}")
        if recvhash == hash:
            print(f"Hashes match. File {file_name} received successfully")
        else:
            print("Hashes do not match. File transfer failed")
            os.remove(f"../../files/{file_name}")
        os.remove(f"../../keys/pubclient.pem")
        busy_flag = 0


    def start_server(self, ip, hostname):
        # threads = []
        data_socket = create_socket(ip, DATA_PORT)
        data_socket.listen()

        greet_socket = create_socket(ip, GREET_PORT)
        greet_socket.listen()

        control_socket = create_socket(ip, CONTROL_PORT)
        control_socket.listen()

        socks = [greet_socket, control_socket]

        print(f"Server listening on socket {ip}")

        while True:
            readable, _, _ = select.select(socks, [], [])

            for i in readable:
                conn, addr = i.accept()
                threading.Thread(
                    target=self.handle_client, args=(conn, addr, data_socket, hostname)
                ).start()




    def openwindow(self):
        self.window = QtWidgets.QMainWindow()
        self.ui = Ui_serverWindow()
        self.ui.setupUi(self.window)
        self.window.show()

    def setupUi(self, MainWindow):
        global ip, iprange, server_thread
        # This is our main window that runs client and we can switch to server from here
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(965, 839)
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")

        # Heading for our main window #Welcome to our EFTP
        self.Heading_label = QtWidgets.QLabel(self.centralwidget)
        self.Heading_label.setGeometry(QtCore.QRect(350, 10, 251, 41))
        font = QtGui.QFont()
        font.setFamily("Times New Roman") # Sets font style
        font.setPointSize(16) #Sets font size
        self.Heading_label.setFont(font)
        self.Heading_label.setAlignment(QtCore.Qt.AlignCenter)
        self.Heading_label.setObjectName("Heading_label")
        
        # This is our label to prompt us to select IP using dropdown # Select IP etc
        self.client_IP_address_label = QtWidgets.QLabel(self.centralwidget)
        self.client_IP_address_label.setGeometry(QtCore.QRect(230, 70, 521, 31))
        font = QtGui.QFont()
        font.setFamily("Times New Roman")
        font.setPointSize(14)
        self.client_IP_address_label.setFont(font)
        self.client_IP_address_label.setAlignment(QtCore.Qt.AlignCenter)
        self.client_IP_address_label.setObjectName("client_IP_address_label")

        # This is our dropdown to select the IP addresses
        self.client_IP_dropdown = QtWidgets.QComboBox(self.centralwidget)
        self.client_IP_dropdown.setGeometry(QtCore.QRect(350, 120, 241, 31))
        self.client_IP_dropdown.setObjectName("client_IP_dropdown")
        
        # We get the available devices and then add the list to the dropdown as our options
        IP_addresses = self.fetch_IP_addresses() # We can fetch IP using function call
        self.client_IP_dropdown.addItems(IP_addresses)

        # We call the print_IP function to display the IP details
        self.client_IP_dropdown.activated.connect(self.print_IP) 
        ip=self.client_IP_dropdown.currentText()
        iprange=get_ip_range(ip)
        

        # This is the label that displays the details of the device
        # For displaying Device Name call your implemented function in the print_IP function
        self.client_device_detail_label = QtWidgets.QLabel(self.centralwidget)
        self.client_device_detail_label.setGeometry(QtCore.QRect(220, 165, 521, 67))
        font = QtGui.QFont()
        font.setFamily("Times New Roman")
        font.setPointSize(12)
        self.client_device_detail_label.setFont(font)
        self.client_device_detail_label.setAlignment(QtCore.Qt.AlignHCenter|QtCore.Qt.AlignTop)
        self.client_device_detail_label.setObjectName("client_device_detail_label")
        self.client_device_detail_label.setText(f'Device Details : \nIP : {self.client_IP_dropdown.currentText()}\nDevice Name : {hostname}')
        # This is where we implement our scan device button
        # From the get_addresses function we can get the IP addresses
        # On clicking the scan devices the function will be called and then you can implement your scan function
        # The available IP addresses as a list will be used as options for the server dropdown which will be added in that function itself
        self.scan_device_button = QtWidgets.QPushButton(self.centralwidget, clicked = lambda: self.get_addresses())
        self.scan_device_button.setGeometry(QtCore.QRect(400, 250, 141, 28))
        font = QtGui.QFont()
        font.setFamily("Times New Roman")
        font.setPointSize(14)
        self.scan_device_button.setFont(font)
        self.scan_device_button.setObjectName("scan_device_button")

        # This is the label that prompts us to select the device to connect to as a server
        # Choose device to connect to label
        self.device_to_connect_label = QtWidgets.QLabel(self.centralwidget)
        self.device_to_connect_label.setGeometry(QtCore.QRect(210, 290, 521, 31))
        font = QtGui.QFont()
        font.setFamily("Times New Roman")
        font.setPointSize(14)
        self.device_to_connect_label.setFont(font)
        self.device_to_connect_label.setAlignment(QtCore.Qt.AlignCenter)
        self.device_to_connect_label.setObjectName("device_to_connect_label")

        # This is the dropdown for the available devices to act as server
        self.devices_available_dropdown = QtWidgets.QComboBox(self.centralwidget)
        self.devices_available_dropdown.setGeometry(QtCore.QRect(310, 330, 331, 31))
        self.devices_available_dropdown.setObjectName("devices_available_dropdown")

        # Based on the selected IP we can perform whatever action we want
        # I will display connection established you can do other things as well
        self.devices_available_dropdown.activated.connect(self.show_connection)

        # This is the label that prompts when connection is established
        self.connection_prompt_label = QtWidgets.QLabel(self.centralwidget)
        self.connection_prompt_label.setGeometry(QtCore.QRect(330, 370, 271, 31))
        font = QtGui.QFont()
        font.setFamily("Times New Roman")
        font.setPointSize(14)
        self.connection_prompt_label.setFont(font)
        self.connection_prompt_label.setAlignment(QtCore.Qt.AlignCenter)
        self.connection_prompt_label.setObjectName("connection_prompt_label")



        # This is the label that reads : "Enter file path"
        self.file_path_label = QtWidgets.QLabel(self.centralwidget)
        self.file_path_label.setGeometry(QtCore.QRect(30, 500, 191, 31))
        font = QtGui.QFont()
        font.setFamily("Times New Roman")
        font.setPointSize(14)
        self.file_path_label.setFont(font)
        self.file_path_label.setAlignment(QtCore.Qt.AlignCenter)
        self.file_path_label.setObjectName("file_path_label")

        # This is the function that takes the file path as input
        # The input is enabled only when the the user wants to send file and he clicks yes
        # The enabling is handled in the yes button clicked under the function enable_file_path()
        self.file_path_input = QtWidgets.QLineEdit(self.centralwidget, placeholderText = 'Enter your file path here', enabled = False)
        self.file_path_input.setGeometry(QtCore.QRect(240, 500, 601, 31))
        self.file_path_input.setText("")
        self.file_path_input.setObjectName("file_path_input")

        # This is the submit button to get the file path
        # On clicking we can fetch the file path and in that function you can perform ping and sending of file etc
        self.submit_file_path = QtWidgets.QPushButton(self.centralwidget, clicked = lambda : self.get_file_path())
        self.submit_file_path.setGeometry(QtCore.QRect(860, 500, 80, 31))
        font = QtGui.QFont()
        font.setFamily("Times New Roman")
        font.setPointSize(14)
        self.submit_file_path.setFont(font)
        self.submit_file_path.setObjectName("submit_file_path")

        # This is the label that displays the session key
        self.session_key_label = QtWidgets.QLabel(self.centralwidget)
        self.session_key_label.setGeometry(QtCore.QRect(50, 560, 871, 61))
        font = QtGui.QFont()
        font.setFamily("Times New Roman")
        font.setPointSize(14)
        self.session_key_label.setFont(font)
        self.session_key_label.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignTop)
        self.session_key_label.setWordWrap(True)
        self.session_key_label.setObjectName("session_key_label")

        # This is the label that displays the file transfer status
        self.file_transfer_label = QtWidgets.QLabel(self.centralwidget)
        self.file_transfer_label.setGeometry(QtCore.QRect(50, 620, 871, 41))
        font = QtGui.QFont()
        font.setFamily("Times New Roman")
        font.setPointSize(14)
        self.file_transfer_label.setFont(font)
        self.file_transfer_label.setObjectName("file_transfer_label")

        # This is the label that displays the file sent successfully
        self.file_sent_success_label = QtWidgets.QLabel(self.centralwidget)
        self.file_sent_success_label.setGeometry(QtCore.QRect(330, 660, 271, 31))
        font = QtGui.QFont()
        font.setFamily("Times New Roman")
        font.setPointSize(14)
        self.file_sent_success_label.setFont(font)
        self.file_sent_success_label.setAlignment(QtCore.Qt.AlignCenter)
        self.file_sent_success_label.setObjectName("file_sent_success_label")

        # This is the label that prompts whether to recieve file or not and become server
        self.recieving_file_request_label = QtWidgets.QLabel(self.centralwidget)
        self.recieving_file_request_label.setGeometry(QtCore.QRect(240, 700, 451, 41))
        font = QtGui.QFont()
        font.setFamily("Times New Roman")
        font.setPointSize(16)
        self.recieving_file_request_label.setFont(font)
        self.recieving_file_request_label.setAlignment(QtCore.Qt.AlignCenter)
        self.recieving_file_request_label.setObjectName("recieving_file_request_label")

        # This is the button to stay as client (basically clicked no)
        # It will stay in client only for now (I put pass in the function that's why)
        self.stay_client_button = QtWidgets.QPushButton(self.centralwidget, clicked = lambda : self.stay_in_client())
        self.stay_client_button.setGeometry(QtCore.QRect(460, 750, 71, 28))
        font = QtGui.QFont()
        font.setFamily("Times New Roman")
        font.setPointSize(14)
        self.stay_client_button.setFont(font)
        self.stay_client_button.setObjectName("stay_client_button")

        # This is the button to go to server (basically clicked yes)
        self.go_to_server_button = QtWidgets.QPushButton(self.centralwidget, clicked = lambda : self.accept())
        self.go_to_server_button.setGeometry(QtCore.QRect(370, 750, 71, 28))
        font = QtGui.QFont()
        font.setFamily("Times New Roman")
        font.setPointSize(14)
        self.go_to_server_button.setFont(font)
        self.go_to_server_button.setObjectName("go_to_server_button")

        # This is UI stuff not required to modify
        MainWindow.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(MainWindow)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 965, 26))
        self.menubar.setObjectName("menubar")
        MainWindow.setMenuBar(self.menubar)
        self.statusbar = QtWidgets.QStatusBar(MainWindow)
        self.statusbar.setObjectName("statusbar")
        MainWindow.setStatusBar(self.statusbar)
        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

        self.client_device_detail_label.setText(f'Device Details : \nIP : {self.client_IP_dropdown.currentText()}\nDevice Name : {hostname}')

    # This dummy function is to get the IP addresses of the client

    def fetch_IP_addresses(self):
        return ip_addr


    def accept(self):
        global user_input
        user_input='yes'

    # This dummy function prints the device details 
    def print_IP(self):
        global ip, iprange, thread
        self.client_device_detail_label.setText(f'Device Details : \nIP : {self.client_IP_dropdown.currentText()}\nDevice Name : {hostname}')
        ip=self.client_IP_dropdown.currentText()
        iprange=get_ip_range(ip)
        print(ip)
        thread=threading.Thread(target=self.start_server, args=(ip, hostname)).start()
        # Here for Device Name you can import your function to get the device name

    # This dummy function is to get the available IP addresses of possible servers
    def get_addresses(self):
        self.run_scan(iprange)
        available_IP = list(set(devices))
        available_IP = [f'{i[0]} ({i[1]})' for i in available_IP]
        self.devices_available_dropdown.clear()
        self.devices_available_dropdown.addItems(available_IP)

    # This dummy function is to display the connection established
    def show_connection(self):
        self.connection_prompt_label.setText('Connection Established')
        self.file_path_input.setEnabled(1)

    # This dummy function is to enable the file path input on clicking yes to send file
        

    # This dummy function is to handle the case when the file is rejected
    def file_rejected(self):
        pass

    # This dummy function is to get the file path
    # You can update the text of the file_transfer_label to show the progress of file being sent
    # To do that just write : self.file_transfer_label.setText('Sent : f{file_size}/{total_file_size} MBB')
    def get_file_path(self):
        file_path = self.file_path_input.text()
        connip=self.devices_available_dropdown.currentText().split()[0]
        self.connection(connip, file_path, hostname)

    # This dummy function is to stay in client
    def stay_in_client(self):
        pass

    # Don't touch this it's purely UI stuff
    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "MainWindow"))
        self.Heading_label.setText(_translate("MainWindow", "Welcome to our EFTP"))
        self.client_IP_address_label.setText(_translate("MainWindow", "Select IP of the Device that you would like to use"))
        self.client_device_detail_label.setText(_translate("MainWindow", "Device Details : "))
        self.scan_device_button.setText(_translate("MainWindow", "Scan Devices"))
        self.device_to_connect_label.setText(_translate("MainWindow", "Choose device to connect to"))
        self.connection_prompt_label.setText(_translate("MainWindow", ""))
        self.file_path_label.setText(_translate("MainWindow", "Enter File Path : "))
        self.submit_file_path.setText(_translate("MainWindow", "Submit"))
        self.session_key_label.setText(_translate("MainWindow", "Session key sent : "))
        self.file_transfer_label.setText(_translate("MainWindow", "Sent : "))
        self.file_sent_success_label.setText(_translate("MainWindow", "File Sent Successfully"))
        self.recieving_file_request_label.setText(_translate("MainWindow", ""))
        self.stay_client_button.setText(_translate("MainWindow", "No"))
        self.go_to_server_button.setText(_translate("MainWindow", "Yes"))

ip_addr, hostname = ip_util.get_ip()
ip=''
iprange=[]

if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    MainWindow = QtWidgets.QMainWindow()
    ui = Ui_MainWindow()
    ui.setupUi(MainWindow)
    MainWindow.show()
    if not (os.path.isfile("../../keys/public.pem") and 
            os.path.isfile("../../keys/private.der")):
        cu.generateNewKeypair(public_out="public.pem", private_out="private.der")
    ip_addr, hostname = ip_util.get_ip()
    sys.exit(app.exec_())