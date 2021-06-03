""" 
This config file would have the credentials of the remote server and 
the commands to execute.
"""

import getpass

# Server credentials needed for SS
HOST = "192.168.2.22"
print("You're trying to connect to ", HOST)

USERNAME = input("Hostname? ").strip()
PASSWORD = getpass.getpass(prompt = "Password? ")

PORT = 22

# Timeout to wait for an authentication response
TIMEOUT = 10

# .pem file details
PKEY = "" 

# Sample commands to execute
COMMANDS = ["lsdsadsads -all"]

