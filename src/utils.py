import os
from scapy.all import *
from networks import *

def packet_handler(networks):
    def parse_packet(pkt):
        if pkt.haslayer(Dot11Beacon):
            bssid = pkt[Dot11].addr2.replace(':', '')
            essid = pkt[Dot11Elt].info.decode()
            try:
                signal = pkt.dBm_AntSignal
            except:
                signal = 'n/a'
            channel = pkt[Dot11Beacon].network_stats().get('channel')
            for network in networks:
                if network.get_bssid() == bssid:
                    break
            else:
                networks.append(Network(bssid, essid, channel))
    return parse_packet

def change_channel(interface, channel):
    try:
        cmd = 'iw dev {} set channel {}'.format(interface, channel)
        os.system(cmd)
        time.sleep(0.5)
    except Exception as e:
        print('[-] could not change channel: {}'.format(e))
        exit(1)

def scan_channels(interface, bssid, essid, chan, networks):
    if chan:
        channels = chan
    else:
        channels = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]
    for channel in channels:
        try:
            change_channel(interface, channel)
            sniff(iface=interface, prn=packet_handler(networks), timeout=3)
        except Exception:
            pass
    return networks
