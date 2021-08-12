#!/usr/bin/env python3

import sys
import socket
from pyfiglet import Figlet
from datetime import datetime

# Print a banner
banner = Figlet(font="big")
print(banner.renderText("SCANN3R"))

# Ask user to provide a target machine to scan
target = input("Enter a Target to Scan: ")
targetIP = socket.gethostbyname(target)

# Print scanning info
print("+" * 28)
print("| Scanning: {} |".format(targetIP))
print("+" * 28)

# Time when scan started
time1 = datetime.now()

# Scanning ports between 1 and 65535
try:
    print("Port         Status")
    for port in range(1,65536):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        response = s.connect_ex((targetIP, port))
        
        if response == 0:
            print("{}           open".format(port))
        s.close()
        
except KeyboardInterrupt:
    print("Process terminated by Ctrl+C")
    sys.exit()

except socket.gaierror:
    print("Cannot resolve hostname!")
    sys.exit()

except socket.error:
    print("Cannot connect to server!")
    sys.exit()

# Time when scan ended
time2 = datetime.now()

# Calculate the time it took to scan
totalTime = time2 - time1
print("Completed Scan in: {} Seconds".format(totalTime))
