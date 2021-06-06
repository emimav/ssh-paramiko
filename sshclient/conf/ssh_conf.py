""" 
This config file would have the credentials of the remote server and 
the commands to execute.
"""

import getpass

# Server credentials needed for SS
HOST = "127.0.0.1"
print("You're trying to connect to ", HOST)

USERNAME = input("Hostname? ").strip()
PASSWORD = getpass.getpass(prompt = "Password? ")

PORT = 2222

# Timeout to wait for an authentication response
TIMEOUT = 60

# .pem file details
# PKEY = "" 

