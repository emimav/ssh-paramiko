#!/usr/bin/env python3

# sshclient.py for SSH Client in /home/kali/Desktop/sshclient
#
# Made by Emima Vaipan
# Login  <em.vaipan@tutamail.com>
#
# Started on    Thu Jun 3 10:50:11 2021 Kali
# Last update   Thu Jun 3 10:50:11 2021 Kali
#
# Source code:
# https://github.com/paramiko/paramiko/blob/master/demos/interactive.py


""" Connect to a host using the config details in /config/ssh_config.py and execute commands """

import os
import sys
import tty
import time
import socket
import select
import paramiko
import termios
import getpass
import subprocess
import logging

from conf import ssh_conf as conf_file

logging.basicConfig()
logging.getLogger("paramiko").setLevel(logging.DEBUG)


class ClientSSH:
    """Class to connect to remote server"""

    def __init__(self):
        """Initialize required variables"""

        self.client = None
        self.host = conf_file.HOST
        self.username = conf_file.USERNAME
        self.password = conf_file.PASSWORD
        self.timeout = float(conf_file.TIMEOUT)
        self.port = conf_file.PORT

    def connect(self):
        """Login to remote servers"""

        try:
            # Paramiko.SSHClient can be used to make connections to the remote
            # server and transfer files
            print("Trying to establish an SSH connection...")

            # Create the SSH client
            self.client = paramiko.SSHClient()
            # Parsing an instance of the AutoAddPolicy to
            # set_missing_host_key_policy() changes it to allow any host
            # Change to MissingHostKeyPolicy
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            # Connect to the server

            """if (self.password == ''):
                self.pkey = paramiko.RSAKey.from_private_key_file(self.pkey)
                self.client.connect(
                    hostname=self.host,
                    port=self.port,
                    username=self.username,
                    pkey=self.pkey,
                    timeout=self.timeout,
                    allow_agent=False,
                    look_for_keys=False)"""

            self.client.connect(
                hostname=self.host,
                port=self.port,
                username=self.username,
                password=self.password,
                timeout=self.timeout,
                allow_agent=False,
                look_for_keys=False)
            print("Connected to the server", self.host)

        except paramiko.AuthenticationException:
            print("Authentication failed, please check your credentials")
            connection_flag = False
            self.client.close()

        except paramiko.SSHException as sshException:
            print("Could not establish SSH connection: %s" % sshException)
            connection_flag = False
            # pass
            self.client.close()

        except socket.timeout as e:
            print("Connection timeout out!")
            connection_flag = False
            self.client.close()

        except Exception as e:
            print("\nException in connecting to the server")
            print("Python says:", e)
            connection_flag = False
            self.client.close()

        else:
            connection_flag = True

            return connection_flag

    def open_pty(self):
        """Opens a pty on a remote server, and allow interactive commands to be run"""

        # Store the current terminal settings to restore them after the remote
        # shell is closed
        self.fd = sys.stdin.fileno()
        self.old_terminal_settings = termios.tcgetattr(self.fd)

        # Create a client channel and invoke an ssh shell session with defauly options
        # p.s. a channel behaves like a socket in paramiko       
        self.channel = self.client.invoke_shell()

        try:
            self.new_terminal_settings = sys.stdin.fileno()

            # tty.setraw(self.new_terminal_settings)
            tty.setcbreak(self.new_terminal_settings)

            # Channel timeout equivalent to non-blocking mode
            self.channel.settimeout(0.0)

            # is_alive validates the connection for the ssh session
            is_alive = True

            # Loop forever, CTRL-C is used to break the tail
            while is_alive:

                tty_height, tty_width = subprocess.check_output(
                    ['stty', 'size']).split()

                try:

                    # Resize  pty to match terminal size
                    self.channel.resize_pty(
                        width=int(tty_width), height=int(tty_height))

                # Catch failures to resize due to a closed connection
                except paramiko.SSHException as sshException:
                    pass

                # Use standard input and a socket in a select loop to process responses
                # from server
                # Readables handles inputs, writeables handles outputs, exceptions handles exceptional
                # conditions
                # Use select calls to examine the status of fd of open
                # input/output channels
                readables, writeables, exceptions = \
                    select.select([self.channel, sys.stdin], [], [])

                if self.channel in readables:

                    # Try to read from the remote end and print to screen
                    try:

                        # Receive data from the channel
                        channel_data = self.channel.recv(1024)

                        # If there is an empty buffer, than the ssh session has
                        # been closed
                        if len(channel_data) == 0:
                            is_alive = False
                        else:

                            # Decode and print server responses
                            print(channel_data.decode(), end='')

                            # Use flush() to force the buffer to empty and
                            # write to screen
                            sys.stdout.flush()

                    except socket.timeout:
                        print("Connection Timeout!")
                        pass

                if sys.stdin in readables and is_alive:

                    char = os.read(self.new_terminal_settings, 1)

                    if len(char) == 0:
                        is_alive = False
                    else:
                        self.channel.send(char)

            self.channel.shutdown(2)

        except KeyboardInterrupt:
            print("\n\nCaught keyboard interrupt. Exiting :(")
            self.channel.shutdown(2)
            self.client.close()

        finally:
            # Restore terminal settings
            termios.tcsetattr(
                sys.stdin,
                termios.TCSAFLUSH,
                self.old_terminal_settings)
            print('SSH channel closed.')


if __name__ == "__main__":

    # Initialise SSH object
    ssh_object = ClientSSH()

    # Connect to the server
    ssh_object.connect()
    ssh_object.open_pty()
