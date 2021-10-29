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

    def probe_network(self):
        pass
