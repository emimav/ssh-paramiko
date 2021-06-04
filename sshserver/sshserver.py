#!/usr/bin/env python3

""" SSH Server implementation based on Paramiko module
    Useful resources: http://docs.paramiko.org/en/stable/api/server.html
                      https://github.com/paramiko/paramiko/blob/master/demos/demo_server.py

"""


import sys
import paramiko
import socket
import threading
import logging


# Set up logging to file
logging.basicConfig(
    filename="log_file_name.log",
    level=logging.INFO,
    format="[%(asctime)s] {%{pathname)s:%(lineno)d} %(levelname)s - %(message)s",
    datefmt="%H:%M:%S")

# Set up logging to console
console = logging.StreamHandler()
console.setLevel(logging.DEBUG)

# Set up an easy-to-read format on console
formatter = logging.Formatter("%(name)-12s: %(levelname)-8s %(message)s")
console.setFormatter(formatter)
logging.getLogger("").addHandler(console)

logger = logging.getLogger(__name__)


class ParamikoServer(paramiko.ServerInterface):
    """

    Class to define an interface to initiate server connections.
    Includes some of the functions to handle client requests e.g. to authenticate.

    """

    def __init__(self, username=None, password=None):
        self.username = username
        self.password = password
        #
        self.event = threading.Event()

    def get_allowed_auths(self, username):
        # return "password, publickey"
        return "password"

    # Check if the client can open channels without further authentication
    def check_auth_none(self, username, password=None):
        if auth_none(self.username):
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    # Check if the credentials provided by the client are valid for
    # authentication

    def check_auth_password(self, username, password):
        if self.username == username and self.password == password:
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    # Check if the  client will be provided with a channel considering the 'kind' of
    # channel they would like to open
    def check_channel_request(self, kind, channel_id):
        logger.debug("Channel requested: %s %s" % (kind, channel_id))
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    # Check if the client will be provided with a shell on the given channel
    # Returns true if the channel gets hooked up to a shell
    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    # Check if the client will be provided with a pseudo-terminal of x dimensions on the given channel
    # Returns True if the pty has been allocated
    def check_channel_pty_request(
            self,
            channel,
            term,
            width,
            height,
            pixelwidth,
            pixelheight,
            modes):
        print("PTY requested")
        return True

    # Display pre-authentication banner to the user
    def get_banner(self):
        return "Let's test this!!!"

    # Allow users to control the SSH banner timeout
    # Allow client code to access the stored SSH server banner via
    # Transport.get_banner


class SSHServer:
    """
    Class to define an SSH2 server and its behaviour e.g start/stop the server, establish TCP/IP connection with a client.
    :param host: IP address of the client
    :param port: Port to use for the connection

    """

    def __init__(self, host, port):
        """ Initialise reader class for connection """

        self.host = host
        self.port = port

    def listen(self):
        try:
            # Create a socket
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind((self.host, self.port))
        except Exception as e:
            print("[-] Bind failed: " + str(e))
            sys.exit(1)

        try:
            self.sock.listen(100)
            print("[+] Listening for a connection ... ")
            client, addr = self.sock.accept()
            print("[+] Accepted connection {0} {1}".format(addr[0], addr[1]))
        except Exception as e:
            print("[-] Listen/Accept failed: " + str(e))
            sys.exit(1)
"""
    def handle_connection(self, client):
        t = paramiko.Transport(client)
        server = ParamikoServer()

        # Start the connect negotiation
        try:
            t.start_server(server=server)
        except EOFError:
            self._dbg(1, "Client disappeared before establishing connection")
            t.close()
            client.close()
            raise

        # Validate that the connection succeeded
        if not t.is_active():
            self._dbg(1, "Client negotiation failed")
            t.close()
            client.close()
            return

        # Wait for authentication
        channel = t.accept(20)
        
        if channel is None:
            self._dbg(1, "Client disappeared before requesting channel.")
            t.close()
            # return
            sys.exit(1)
        print("[+] Authenticated!")

        channel.settimout(self.timeout)

        try:
            # Wait for shell request
            server.event.wait(10)
            if not serve.event.isSet():
                self._dbg(1, "Client never asked for a shell.")
            t.close()

"""
if __name__ == "__main__":

    # Initialise SSH object
    ssh_server = SSHServer('127.0.0.1', 2222)
    ssh_server.listen()


