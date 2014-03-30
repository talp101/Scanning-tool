from scapy.layers.inet import TCP, IP

__author__ = 'tal'
from scapy.all import *


class Scanner():
    def __init__(self, dst_ip, src_ip):
        self.dst_ip = dst_ip
        self.src_ip = src_ip
        self.src_port = RandShort()
        self.dst_ports = [80]
        self.results = {1: "Open", 2: "Closed", 3: "Filtered"}

    def tcp_scan(self):
        # p = IP(dst=self.dst_ip, src=self.src_ip) / TCP(sport=self.src_port, dport=80, flags="S")
        resp = sr1(IP(dst=self.dst_ip, src=self.src_ip) / TCP(sport=self.src_port, dport=80, flags="S"), timeout=10)
        if str(type(resp)) == "<type 'NoneType'>":
            print self.results[2]
        elif resp.haslayer(TCP):
            if resp.getlayer(TCP).flags == 0x12:
                send_rst = sr(
                    IP(dst=self.dst_ip, src=self.src_ip) / TCP(sport=self.src_port, dport=80, flags="AR"),
                    timeout=10)
                print self.results[1]
            elif resp.getlayer(TCP).flags == 0x14:
                print self.results[2]

    def udp_scan(self):
        pass

    def ack_scan(self):
        pass

    def stealth_connection(self):
        pass

    def fin_scan(self):
        """
        Purpose: Send a fin packet over tcp, target should send back RST
        """
        p = IP(dst=self.dst_ip) / TCP(dport=self.dst_ports, flags="F")
        result = sr1(p)

