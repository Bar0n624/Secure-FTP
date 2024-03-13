# Note all function implementations is done at the end of setupUi function
# The function names are self explanatory and the comments are also there to help you understand the flow

from PyQt5 import QtCore, QtGui, QtWidgets

class Ui_serverWindow(object):
    def setupUi(self, serverWindow):
        serverWindow.setObjectName("serverWindow")
        serverWindow.resize(995, 826)
        self.centralwidget = QtWidgets.QWidget(serverWindow)
        self.centralwidget.setObjectName("centralwidget")

        # This is the server Heading Label # Recieve files here
        self.server_heading_label = QtWidgets.QLabel(self.centralwidget)
        self.server_heading_label.setGeometry(QtCore.QRect(370, 20, 251, 51))
        font = QtGui.QFont()
        font.setFamily("Times New Roman")
        font.setPointSize(16)
        self.server_heading_label.setFont(font)
        self.server_heading_label.setAlignment(QtCore.Qt.AlignCenter)
        self.server_heading_label.setObjectName("server_heading_label")

        # This is our label to prompt us to select IP using dropdown # Select IP etc
        self.server_select_IP_label = QtWidgets.QLabel(self.centralwidget)
        self.server_select_IP_label.setGeometry(QtCore.QRect(250, 70, 491, 51))
        font = QtGui.QFont()
        font.setFamily("Times New Roman")
        font.setPointSize(16)
        self.server_select_IP_label.setFont(font)
        self.server_select_IP_label.setAlignment(QtCore.Qt.AlignCenter)
        self.server_select_IP_label.setObjectName("server_select_IP_label")

        # This is our dropdown to select the IP addresses
        self.server_IP_dropdown = QtWidgets.QComboBox(self.centralwidget)
        self.server_IP_dropdown.setGeometry(QtCore.QRect(340, 130, 311, 41))
        self.server_IP_dropdown.setObjectName("server_IP_dropdown")

        # We get the available devices and then add the list to the dropdown as our options
        server_IP_addresses = self.server_fetch_IP_addresses() # We can fetch IP using function call
        self.server_IP_dropdown.addItems(server_IP_addresses)

        # We call the print_IP function to display the IP details
        # You can add the server socket as well in the function
        self.server_IP_dropdown.activated.connect(self.server_print_IP)

        # This is the label that displays the details of the device
        # For displaying Device Name call your implemented function in the print_IP function
        self.server_details_label = QtWidgets.QLabel(self.centralwidget)
        self.server_details_label.setGeometry(QtCore.QRect(240, 180, 491, 101))
        font = QtGui.QFont()
        font.setFamily("Times New Roman")
        font.setPointSize(14)
        self.server_details_label.setFont(font)
        self.server_details_label.setAlignment(QtCore.Qt.AlignHCenter|QtCore.Qt.AlignTop)
        self.server_details_label.setObjectName("server_details_label")

        # This is the label that displays the connection established with the client
        self.connection_establish_label = QtWidgets.QLabel(self.centralwidget)
        self.connection_establish_label.setGeometry(QtCore.QRect(50, 300, 901, 51))
        font = QtGui.QFont()
        font.setFamily("Times New Roman")
        font.setPointSize(16)
        self.connection_establish_label.setFont(font)
        self.connection_establish_label.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.connection_establish_label.setObjectName("connection_establish_label")

        # This is the label that displays the incoming file request info
        self.file_request_info_server_label = QtWidgets.QLabel(self.centralwidget)
        self.file_request_info_server_label.setGeometry(QtCore.QRect(50, 360, 901, 71))
        font = QtGui.QFont()
        font.setFamily("Times New Roman")
        font.setPointSize(16)
        self.file_request_info_server_label.setFont(font)
        self.file_request_info_server_label.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignTop)
        self.file_request_info_server_label.setWordWrap(True)
        self.file_request_info_server_label.setObjectName("file_request_info_server_label")

        # This is the label that asks if we want to accept the file
        self.accept_file_label = QtWidgets.QLabel(self.centralwidget)
        self.accept_file_label.setGeometry(QtCore.QRect(280, 480, 431, 51))
        font = QtGui.QFont()
        font.setFamily("Times New Roman")
        font.setPointSize(16)
        self.accept_file_label.setFont(font)
        self.accept_file_label.setAlignment(QtCore.Qt.AlignCenter)
        self.accept_file_label.setObjectName("accept_file_label")

        # This is the button to accept the file
        self.accepting_file_button = QtWidgets.QPushButton(self.centralwidget, clicked = lambda : self.accept_file())
        self.accepting_file_button.setGeometry(QtCore.QRect(370, 540, 81, 41))
        font = QtGui.QFont()
        font.setFamily("Times New Roman")
        font.setPointSize(14)
        self.accepting_file_button.setFont(font)
        self.accepting_file_button.setObjectName("accepting_file_button")

        # This is the button to reject the file
        self.rejecting_file_button = QtWidgets.QPushButton(self.centralwidget)
        self.rejecting_file_button.setGeometry(QtCore.QRect(490, 540, 81, 41))
        font = QtGui.QFont()
        font.setFamily("Times New Roman")
        font.setPointSize(14)
        self.rejecting_file_button.setFont(font)
        self.rejecting_file_button.setObjectName("rejecting_file_button")

        # This is the label that displays the file recieving rate
        self.file_recieving_rate_label = QtWidgets.QLabel(self.centralwidget)
        self.file_recieving_rate_label.setGeometry(QtCore.QRect(40, 610, 901, 51))
        font = QtGui.QFont()
        font.setFamily("Times New Roman")
        font.setPointSize(16)
        self.file_recieving_rate_label.setFont(font)
        self.file_recieving_rate_label.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.file_recieving_rate_label.setObjectName("file_recieving_rate_label")

        # This is the label that displays the file recieve success message
        self.file_recieve_success_label = QtWidgets.QLabel(self.centralwidget)
        self.file_recieve_success_label.setGeometry(QtCore.QRect(280, 690, 431, 51))
        font = QtGui.QFont()
        font.setFamily("Times New Roman")
        font.setPointSize(16)
        self.file_recieve_success_label.setFont(font)
        self.file_recieve_success_label.setAlignment(QtCore.Qt.AlignCenter)
        self.file_recieve_success_label.setObjectName("file_recieve_success_label")

        # This is UI stuff not required to modify
        serverWindow.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(serverWindow)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 995, 26))
        self.menubar.setObjectName("menubar")
        serverWindow.setMenuBar(self.menubar)
        self.statusbar = QtWidgets.QStatusBar(serverWindow)
        self.statusbar.setObjectName("statusbar")
        serverWindow.setStatusBar(self.statusbar)
        self.retranslateUi(serverWindow)
        QtCore.QMetaObject.connectSlotsByName(serverWindow)

    # This dummy function is to get the IP addresses of the client
    def server_fetch_IP_addresses(self):
        return ['192.168.1.1','192.168.1.2','192.168.1.3']
    
    # This dummy function prints the device details 
    def server_print_IP(self):
        self.server_details_label.setText(f'Device Details : \nIP : {self.server_IP_dropdown.currentText()}\nDevice Name : Lenovo\nSocket : {self.server_IP_dropdown.currentText()}')
        # Here for Device Name you can import your function to get the device name and the server socket

    # This dummy function is to accept the file
    # You can update the text of the file_recieving_rate_label to show the progress of file recieving
    # To do that just write : self.file_recieving_rate_label.setText('Recieved : f{file_size}/{total_file_size} MBB')
    def accept_file(self):
        pass

    # Don't touch this it's purely UI stuff
    def retranslateUi(self, serverWindow):
        _translate = QtCore.QCoreApplication.translate
        serverWindow.setWindowTitle(_translate("serverWindow", "MainWindow"))
        self.server_heading_label.setText(_translate("serverWindow", "Recieve Files Here !"))
        self.server_select_IP_label.setText(_translate("serverWindow", " Choose which IP you would like to Use : "))
        self.server_details_label.setText(_translate("serverWindow", "Device Details : "))
        self.connection_establish_label.setText(_translate("serverWindow", "Connection established with : "))
        self.file_request_info_server_label.setText(_translate("serverWindow", "Incoming file request"))
        self.accept_file_label.setText(_translate("serverWindow", "Would you like to accept ?"))
        self.file_recieving_rate_label.setText(_translate("serverWindow", "Recieved : "))
        self.accepting_file_button.setText(_translate("serverWindow", "Yes"))
        self.rejecting_file_button.setText(_translate("serverWindow", "No"))
        self.file_recieve_success_label.setText(_translate("serverWindow", "File recieved successfully !"))

if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    serverWindow = QtWidgets.QMainWindow()
    ui = Ui_serverWindow()
    ui.setupUi(serverWindow)
    serverWindow.show()
    sys.exit(app.exec_())
