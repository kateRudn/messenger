from app import design
from app import time, socket, threading, rsa, json
from app import crypto_utils
from threading import Thread
import random
import sys
from PyQt5 import QtWidgets
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QMessageBox


class Client(QtWidgets.QMainWindow, design.Ui_MainWindow):
    def __init__(self):
        super().__init__()
        self.setupUi(self)  # инициализация дизайна

        self.ip = '127.0.0.1'
        self.port = 5555

        self.username = None

        # Ключ шифрования сервера
        self.server_public_key_n = None
        self.server_public_key_e = None

        # Ключи шифрования текущего клиента
        (self.public_key, self.private_key) = rsa.newkeys(1024)

        self.session_key = None

        self.list_users = {}

        self.t = None

        self.pushButton.clicked.connect(self.connect_server)
        self.pushButton_2.clicked.connect(self.send_message)
        self.listWidget.itemClicked.connect(self.show_chat)

    def show_users(self):
        self.listWidget.clear()
        for k, v in self.list_users.items():
            self.listWidget.addItem(k)

    def show_chat(self, item):
        for i in range (self.listWidget.count()):
            if self.listWidget.item(i)!=item:
                self.listWidget.item(i).setBackground(Qt.white)
        item.setBackground(Qt.blue)
        self.plainTextEdit.clear()
        friend = self.listWidget.currentItem().text()
        if (len(self.list_users[friend]) > 0):
            for m in self.list_users[friend]:
                self.plainTextEdit.appendPlainText(m)

    def send_message(self):
        friend = self.listWidget.currentItem().text()
        try:
            if len(self.lineEdit_2.text()) > 0 and friend != "":
                message = self.lineEdit_2.text()
                crypto_message = crypto_utils.aes_encrypt(message.encode(), crypto_utils.i_to_b(self.session_key))
                self.list_users[friend].append("[Вы]: " + message)
                self.plainTextEdit.appendPlainText(f'[Вы]: {message}')
                dict_message = {}
                dict_message.update({"type" : "message"})
                dict_message.update({"to": friend})
                dict_message.update({"message": crypto_message.decode()})
                digest = crypto_utils.create_digest(message.encode(), self.private_key['d'], self.private_key['n'])
                dict_message.update({"digest": str(digest)})
                dict_message.update({"n" : str(self.public_key['n'])})
                dict_message.update({"e": str(self.public_key['e'])})
                self.tcp_client.send(self.dict_to_json(dict_message))
                self.lineEdit_2.clear()
        except:
            msg = QMessageBox()
            msg.setIcon(QMessageBox.Critical)
            msg.setText("Ошибка отправки сообщения")
            msg.setInformativeText('Выберите собеседника и напишите сообщение!')
            msg.setWindowTitle("Ошибка")
            msg.exec_()

    def listen_for_messages(self):
        while True:
            message = self.tcp_client.recv(1024)
            dict_message = json.loads(message)
            if dict_message['type'] == "server_pub_key":
                self.server_public_key_n = int(dict_message['n'])
                self.server_public_key_e = int(dict_message['e'])
                self.session_key = random.getrandbits(128)
                dict_key = {}
                dict_key.update({"type" : "session_key"})
                decr_session_key = crypto_utils.rsa_cipher(self.session_key, self.server_public_key_e, self.server_public_key_n)
                dict_key.update({"key": str(decr_session_key)})
                self.tcp_client.send(self.dict_to_json(dict_key))
            if dict_message['type'] == "error":
                if dict_message['response'] == "invalid name":
                    self.tcp_client.close()
                    self.username = None
                    self.lineEdit.setEnabled(True)
                    self.lineEdit.clear()
                    self.lineEdit.setPlaceholderText("input new login")
                    self.pushButton.setEnabled(True)
                if dict_message['response'] == "user is offline":
                    friend = dict_message['user']
                    self.list_users[friend].append("----------------Пользователь вышел из сети----------------")
                    for i in range(self.listWidget.count()):
                        if self.listWidget.item(i).text() == friend:
                            self.listWidget.item(i).setBackground(Qt.red)
            if dict_message['type'] == "list":
                for u in dict_message['list']:
                    if u != self.username and u not in self.list_users:
                        self.list_users.update({u : []})
                        self.listWidget.addItem(u)
            if dict_message['type'] == "new_user":
                if dict_message['user'] != self.username and dict_message['user'] not in self.list_users:
                    self.list_users.update({dict_message['user']: []})
                    self.listWidget.addItem(dict_message['user'])
            if dict_message['type'] == "disconnect":
                user = dict_message['user']
                if (len(self.list_users[user]) == 0):
                    del self.list_users[user]
                self.show_users()
            if dict_message['type'] == "message":
                friend = dict_message['from']
                encr_message = dict_message['message']
                message = crypto_utils.aes_decrypt(encr_message.encode(), crypto_utils.i_to_b(self.session_key))
                digest = int(dict_message['digest'])
                n = int(dict_message['n'])
                e = int(dict_message['e'])
                if (not crypto_utils.verify_digest(message, digest, e, n)):
                    message = "~Поврежденное сообщение~".encode()
                self.list_users[friend].append(message.decode())
                for i in range(self.listWidget.count()):
                    if self.listWidget.item(i).text() == friend:
                        self.listWidget.item(i).setBackground(Qt.red)

    def connect_server(self):
        if (self.lineEdit.text() == ""):
            self.lineEdit.setStyleSheet("QLineEdit { border : 1px solid black; border-color: red;}")
        else:
            self.lineEdit.setStyleSheet("QLineEdit { border : 1px solid black; border-color: black;}")

        try:
            self.tcp_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.tcp_client.connect((self.ip, self.port))
            time.sleep(1)

            # Запускаем мониторинг входящих сообщений
            self.t = Thread(target=self.listen_for_messages)
            self.t.daemon = True
            self.t.start()

            username = {}
            username.update({"type": "name"})
            username.update({"user": self.lineEdit.text()})
            self.username = self.lineEdit.text()
            self.tcp_client.send(self.dict_to_json(username))

            # Производим действия с объектами
            self.lineEdit.setEnabled(False)
            self.pushButton.setEnabled(False)
        except:
            msg = QMessageBox()
            msg.setIcon(QMessageBox.Critical)
            msg.setText("Ошибка подключения к серверу")
            msg.setInformativeText('Повторите попытку позже!')
            msg.setWindowTitle("Ошибка")
            msg.exec_()
            self.lineEdit.clear()

    def dict_to_json(self, dict_message):
        return json.dumps(dict_message).encode('utf-8')

    # Закрытия соединения
    def closeEvent(self, event):
        try:
            dict_logout = {}
            dict_logout.update({"type" : "logout"})
            self.tcp_client.send(self.dict_to_json(dict_logout))
            self.t.stop()
            self.tcp_client.close()
        except:
            pass

def main():
    app = QtWidgets.QApplication(sys.argv)
    window = Client()
    window.show()
    app.exec_()

if __name__ == '__main__':
    main()