# libraries
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
import paramiko
import socket
import threading

# constraints
logging_format = logging.Formatter('%(message)s')
SSH_BANNER = "SSH-2.0-OpenSSH_7.4"
# host_key file expected in repo root; resolve relative to this file so running from
# another working directory does not break key loading
BASE_DIR = Path(__file__).resolve().parent
HOST_KEY_PATH = BASE_DIR / "server.key"
try:
     host_key = paramiko.RSAKey.from_private_key_file(str(HOST_KEY_PATH))
except FileNotFoundError as exc:
     raise FileNotFoundError(
          f"Host key not found at {HOST_KEY_PATH}. Generate one with 'ssh-keygen -t rsa -b 2048 -f server.key'."
     ) from exc
except paramiko.PasswordRequiredException as exc:
     raise RuntimeError(
          f"Host key at {HOST_KEY_PATH} is encrypted with a passphrase; supply an unencrypted key for the honeypot."
     ) from exc


# loggers and audit files
funnel_logger = logging.getLogger('funnel_logger')
funnel_logger.setLevel(logging.INFO)
funnel_handler = RotatingFileHandler('audits.log', maxBytes=2000, backupCount=5)
funnel_handler.setFormatter(logging_format)
funnel_logger.addHandler(funnel_handler)

creds_logger = logging.getLogger('creds_logger')
creds_logger.setLevel(logging.INFO)
creds_handler = RotatingFileHandler('cmd_audits.log', maxBytes=2000, backupCount=5)
creds_handler.setFormatter(logging_format)
creds_logger.addHandler(creds_handler)


def emulated_shell(channel, client_ip):
     """A tiny emulated shell that echoes input and responds to a few commands."""
     channel.send(b'corporate-jumpbox2$')
     command = b""
     while True:
          char = channel.recv(1)
          if not char:
               # connection closed by client
               channel.close()
               break

          # echo the received character back
          channel.send(char)

          # handle line endings (CR or LF)
          if char in (b'\r', b'\n'):
               command += char
               if command.strip() == b'exit':
                    response = b'\ngood bye..!\n'
                    channel.send(response)
                    channel.close()
                    break
               elif command.strip() == b'pwd':
                    response = b'\n/usr/local/\r\n'
                    creds_logger.info(f"command {command.strip()} executed by {client_ip}")
               elif command.strip() == b'whoami':
                    response = b"\n" + b"corpuser1" + b"\r\n"
                    creds_logger.info(f"command {command.strip()} executed by {client_ip}")
               elif command.strip() == b'ls':
                    response = b'\n' + b'jumpbox1.conf' + b'\r\n'
                    creds_logger.info(f"command {command.strip()} executed by {client_ip}")
               elif command.strip() == b'cat jumpbox1.conf':
                    response = b'\n' + b'Go to deeboodah.com' + b'\r\n'
                    creds_logger.info(f"command {command.strip()} executed by {client_ip}")
               else:
                    response = b"\n" + command.strip() + b"\r\n"
                    creds_logger.info(f"command {command.strip()} executed by {client_ip}")

               channel.send(response)
               channel.send(b'corporate-jumpbox2$')
               command = b""
          else:
               command += char


class Server(paramiko.ServerInterface):
     def __init__(self, client_ip, input_username=None, input_password=None):
          self.event = threading.Event()
          self.client_ip = client_ip
          self.input_username = input_username
          self.input_password = input_password

     def check_channel_request(self, kind: str, chanid: int) -> int:
          if kind == 'session':
               return paramiko.OPEN_SUCCEEDED
          return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

     def get_allowed_auths(self, username):
          return 'password'

     def check_auth_password(self, username, password):
          funnel_logger.info(f"{self.client_ip} - attempted login with username: '{username}' and password: '{password}'")   
          creds_logger.info(f"{self.client_ip} ,{username},{password}")
          if self.input_username is not None and self.input_password is not None:
               if username == self.input_username and password == self.input_password:
                    return paramiko.AUTH_SUCCESSFUL
               else:
                    return paramiko.AUTH_FAILED
          else:
               return paramiko.AUTH_SUCCESSFUL

     def check_channel_shell_request(self, channel):
          self.event.set()
          return True

     def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
          return True

     def check_channel_exec_request(self, channel, command):
          return True


def client_handle(client, addr, username, password):
     client_ip = addr[0]
     print(f"{client_ip} has connected to the server")

     transport = None
     try:
          transport = paramiko.Transport(client)
          transport.local_version = SSH_BANNER
          server = Server(client_ip=client_ip, input_username=username, input_password=password)

          transport.add_server_key(host_key)
          transport.start_server(server=server)

          channel = transport.accept(100)
          if channel is None:
               print("No channel was opened")
               return

          standard_banner = b"Welcome to Ubuntu 22.04 LTS (GNU/Linux 5.15.0-1031-azure x86_64)\r\n"
          channel.send(standard_banner)
          emulated_shell(channel, client_ip)

     except Exception as error:
          print(error)
          print("!!!Error !!!")
     finally:
          if transport is not None:
               try:
                    transport.close()
               except Exception as error:
                    print(error)
                    print("!! Error!! ")
          try:
               client.close()
          except Exception as error:
               print(error)
               print("!! Error!! ")


#Provision SSH-based Honeypot

def honeypot(address, port, username, password):
     socks = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
     socks.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
     socks.bind((address, port))

     socks.listen(100)
     print(f"SSH Server is listening on port {port}.")

     while True:
          try:
               client, addr = socks.accept()
               ssh_honeypot_thread = threading.Thread(target=client_handle, args=(client, addr, username, password))
               ssh_honeypot_thread.start()
          except Exception as error:
               print(error)


if __name__ == '__main__':
     honeypot('127.0.0.1', 2223, username=None, password=None)
