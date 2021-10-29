import netifaces

from scapy.all import *

from utils import *

class Network():
    def __init__(self, bssid, essid, channel):
        self.bssid = bssid
        self.essid = essid
        self.channel = channel
        self.wps_info = {}
    
    def get_bssid(self):
        return self.bssid

    def get_essid(self):
        return self.essid

    def get_channel(self):
        return self.channel

    def get_wps_info(self):
        return self.wps_info

    def probe_network(self, interface, interface_mac):
        src = mac2str(interface_mac)
        dst = mac2str(bssid)
        change_channel(interface, self.channel)

        pkt = RadioTap()/Dot11(addr1=dst, addr2=src, addr3=src)\
            /Dot11ProbeReq()\
            /Dot11Elt(ID=0, info=self.essid)\
            /Dot11Elt(ID=1, info='\x82\x84\x8b\x96\x0c\x12\x18')\
            /Dot11Elt(ID=50, info='\x30\x48\x60\x6b')\
            /Dot11Elt(ID=3, info=chr(self.channel))
        answer = srp1(pkt, iface=interface, verbose=0)
        answer.show()

