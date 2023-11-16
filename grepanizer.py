#!/usr/bin/env python3

# Author: @4ndymcfly
# Date: 16/11/2023

import sys
import re
from collections import defaultdict

def analyze_nmap_output(filename):
    # Initialize a dictionary to store the results
    results = defaultdict(list)

    # Open the file and read the nmap output
    with open(filename, 'r') as file:
        nmap_output = file.read()

    # Split the nmap output into lines
    lines = nmap_output.split("\n")

    # Iterate over each line
    for line in lines:
        # Look for lines that contain port information
        if "Ports:" in line:
            # Extract the IP and port details
            ip = line.split()[1]
            ports = line.split("Ports:")[1].split(", ")

            # Iterate over each port
            for port in ports:
                # Extract the port number and remove extra spaces
                port_number = port.split("/")[0].strip()

                # Extract the port description
                port_description = port.split("/")[4]

                # Add the IP and port description to the results dictionary for this port
                # Only if the IP is not already in the list for this port
                if ip.split(".")[-1] not in results[port_number]:
                    results[port_number].append((ip.split(".")[-1], port_description))  # Only the last octet of the IP

    # Sort the results by port number
    sorted_results = dict(sorted(results.items(), key=lambda item: int(item[0])))

    # Print the results
    print("\n", end="")
    color_switch = True
    for port, ips in sorted_results.items():
        descriptions = set(ip[1] for ip in ips if ip[1] != ",")
        if color_switch:
            print(f"\033[94mPORT \033[0m {port}\t{', '.join(descriptions).ljust(16)}\t\033[94mIP \033[0m {', '.join(ip[0] for ip in ips)}")
        else:
            print(f"\033[90mPORT \033[0m {port}\t{', '.join(descriptions).ljust(16)}\t\033[90mIP \033[0m {', '.join(ip[0] for ip in ips)}")
        color_switch = not color_switch

# Call the function with the name of your file
if __name__ == "__main__":
    analyze_nmap_output(sys.argv[1])
