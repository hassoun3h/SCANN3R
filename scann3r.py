#!/usr/bin/env python3

import sys
import socket
from pyfiglet import Figlet
from datetime import datetime

#Print a banner
custom_fig = Figlet(font="big")
print(custom_fig.renderText("SCANN3R"))

#Ask user to  provide a target machine to scan
target = input("Enter a Target to Scan: ")
targetIP = socket.gethostbyname(target)

#Print a banner
print("+" * 28)
print("| Scanning: {} |".format(targetIP))
print("+" * 28)

#Calculate time when scan started
time1 = datetime.now()

#Scanning ports betwwn 1 and 65535
try:
    print("Port         Status")
    for port in range(1,65536):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        response = s.connect_ex((targetIP, port))
        
        if response == 0:
            print("{}           open".format(port))
        s.close()
except KeyboardInterrupt:
    print("Process Terminated By Ctrl+C")
    sys.exit()

except socket.gaierror:
    print("Cannot Resolve Hostname!")
    sys.exit()

except socket.error:
    print("Cannot Connect to Server!")
    sys.exit()

#Calculate time when scan ended
time2 = datetime.now()

#Calculate the time it took to scan
totalTime = time2 - time1
print("Completed Scan in: {} Seconds".format(totalTime))
