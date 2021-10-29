import os
import netifaces

from scapy.all import *

def packet_handler(networks):
    def parse_packet(pkt):
        if pkt.haslayer(Dot11Beacon):
            bssid = pkt[Dot11].addr2
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
        except Exception as e:
            print('[-] could not sniff channel: {}'.format(e))
    return networks

def get_interface_mac(interface):
    addrs = netifaces.ifaddresses(interface)
    return addrs[netifaces.AF_LINK][0]['addr']

class Network():
    def __init__(self, bssid, essid, channel):
        self.bssid = bssid
        self.essid = essid
        self.channel = channel
        self.probed = False
        self.wps_info = {}
    
    def get_bssid(self):
        return self.bssid

    def get_essid(self):
        return self.essid

    def get_channel(self):
        return self.channel

    def get_wps_info(self):
        return self.wps_info

    def set_probed(self):
        self.probed = True

    def probe_network(self, interface, interface_mac):
        src = mac2str(interface_mac)
        dst = mac2str(self.bssid)
        change_channel(interface, self.channel)

        pkt = RadioTap()/Dot11(addr1=dst, addr2=src, addr3=src)\
            /Dot11ProbeReq()\
            /Dot11Elt(ID=0, info=self.essid)\
            /Dot11Elt(ID=1, info='\x82\x84\x8b\x96\x0c\x12\x18')\
            /Dot11Elt(ID=50, info='\x30\x48\x60\x6c')\
            /Dot11Elt(ID=3, info=chr(self.channel))
        answer = srp1(pkt, iface=interface, verbose=0, timeout=2)
        if answer:
            answer.show()
        return answer
