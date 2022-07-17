from app import time, socket, threading, rsa, json
from app import crypto_utils

class Server:
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port
        self.all_client = [] # список сокетов
        self.client = {} # словарь с именами и сокетами клиентов
        self.client_key = {} # словарь с кючами и именами клиентов

        self.private_key = None
        self.public_key = None
        (self.public_key, self.private_key) = rsa.newkeys(1024)

        # Запускаем прослушивание соединений
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind((self.ip, self.port))
        self.server.listen(0)
        threading.Thread(target=self.connect_handler).start()
        print('Сервер запущен!')

    # Обрабатываем входящие соединения
    def connect_handler(self):
        while True:
            client, address = self.server.accept()
            if client not in self.all_client:
                self.all_client.append(client)
                threading.Thread(target=self.message_handler, args=(client,)).start()
            time.sleep(1)

    # Обрабатываем отправленный текст
    def message_handler(self, client_socket):
        while True:
            message = client_socket.recv(1024)
            dict_message = json.loads(message)
            if dict_message['type'] == "name":
                if dict_message['user'] not in self.client:
                    self.client.update({dict_message['user'] : client_socket})
                    print ("User " + dict_message['user'] + " connect to server")
                    if len(self.client) > 1:
                        list_client = []
                        for k, v in self.client.items():
                            if k != dict_message['user']:
                                list_client.append(k)
                        dict_list_client = {}
                        dict_list_client.update({"type" : "list"})
                        dict_list_client.update({"list": list_client})
                        client_socket.send(self.dict_to_json(dict_list_client))
                    for cl in self.all_client:
                        dict_new_user = {}
                        dict_new_user.update({"type": "new_user"})
                        dict_new_user.update({"user": dict_message['user']})
                        if cl != client_socket:
                            cl.send(self.dict_to_json(dict_new_user))
                    pub_key = {}
                    pub_key.update({"type": "server_pub_key"})
                    pub_key.update({"n": str(self.public_key['n'])})
                    pub_key.update({"e": str(self.public_key['e'])})
                    client_socket.send(self.dict_to_json(pub_key))
                else:
                    dict_error = {}
                    dict_error.update({"type" : "error"})
                    dict_error.update({"response": "invalid name"})
                    client_socket.send(self.dict_to_json(dict_error))
                    self.all_client.remove(client_socket)
            if dict_message['type'] == "session_key":
                decr_session_key = int(dict_message['key'])
                session_key = crypto_utils.rsa_cipher(decr_session_key, self.private_key['d'], self.private_key['n'])
                username = self.get_key(self.client, client_socket)
                self.client_key[username] = session_key
            if dict_message['type'] == "message":
                to = dict_message['to']
                encr_message = dict_message['message']
                usr = self.get_key(self.client, client_socket)
                try:
                    message = crypto_utils.aes_decrypt(encr_message.encode(), crypto_utils.i_to_b(self.client_key[usr]))
                    encr_message = crypto_utils.aes_encrypt(message, crypto_utils.i_to_b(self.client_key[to]))
                    dict_mess = {}
                    dict_mess.update({"type" : "message"})
                    dict_mess.update({"from": usr})
                    dict_mess.update({"message": encr_message.decode()})
                    dict_mess.update({"digest": dict_message['digest']})
                    dict_mess.update({"n": dict_message['n']})
                    dict_mess.update({"e": dict_message['e']})
                    self.client[to].send(self.dict_to_json(dict_mess))
                except:
                    dict_error = {}
                    dict_error.update({"type": "error"})
                    dict_error.update({"response": "user is offline"})
                    dict_error.update({"user": to})
                    client_socket.send(self.dict_to_json(dict_error))
            if dict_message['type'] == "logout":
                self.all_client.remove(client_socket)
                cl = self.get_key(self.client, client_socket)
                print("User " + cl + " is disconnect")
                del self.client[cl]
                del self.client_key[cl]
                dict_discnct = {}
                dict_discnct.update({"type" : "disconnect"})
                dict_discnct.update({"user": cl})
                for usr in self.all_client:
                    usr.send(self.dict_to_json(dict_discnct))
                break
            time.sleep(1)

    def dict_to_json(self, dict_message):
        return json.dumps(dict_message).encode('utf-8')

    def get_key(self, d, value):
        for k, v in d.items():
            if v == value:
                return k

myserver = Server('127.0.0.1', 5555)