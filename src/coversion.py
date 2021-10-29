#!/usr/bin/env python3

import argparse
import time

from networks import *
from utils import *

def get_args():
    parser = argparse.ArgumentParser(description='Coversion Argument Parser')
    parser.add_argument('-i', '--interface', required=True, help='Wireless interface')
    parser.add_argument('-c', '--channel', help='Wireless channel')
    parser.add_argument('-b', '--bssid', help='BSSID')
    parser.add_argument('-e', '--essid', help='ESSID')
    parser.add_argument('-p', '--probe-all', help='Probe all available networks')
    parser.add_argument('-V', '--version', help='Show version info')
    return parser.parse_args()

def main():
    networks = []
    args = get_args()
    interface_mac = get_interface_mac(args.interface)
    scan_channels(args.interface, args.bssid, args.essid, args.channel, networks)
    
if __name__ == "__main__":
    main()
