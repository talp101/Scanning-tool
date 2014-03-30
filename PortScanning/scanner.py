__author__ = 'tal'
from scapy.all import *


class Scanner():
    def __init__(self, dst_ip, src_ip):
        self.dst_ip = dst_ip
        self.src_ip = src_ip

    def tcp_scan(self):
        pass

    def udp_scan(self):
        pass

    def ack_scan(self):
        pass

    def stealth_connection(self):
        pass

    def fin_scan(self):
        pass