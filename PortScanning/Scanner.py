from scapy.layers.inet import TCP, IP, ICMP, UDP

__author__ = 'tal'
import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import socket


class Scanner():
    def __init__(self, dst_ip, src_ip):
        self.dst_ip = socket.gethostbyname(dst_ip)
        # self.dst_ip = dst_ip
        self.src_ip = src_ip
        self.src_port = RandShort()
        self.dst_ports = 80
        self.results = {1: "Open", 2: "Closed", 3: "Filtered"}

    def set_print(self, ip, port, state):
        print ip, ':', port, "- ", state

    def tcp_scan(self):
        for port in [21, 23, 25, 53, 80, 110, 443]:
            resp = sr1(IP(dst=self.dst_ip) / TCP(sport=self.src_port, dport=port, flags="S"), timeout=2, verbose=0)
            if str(type(resp)) == "<type 'NoneType'>":
                self.set_print(self.dst_ip, port, self.results[2])
            elif resp.haslayer(TCP):
                if resp.getlayer(TCP).flags == 0x12:
                    send_rst = sr(IP(dst=self.dst_ip) / TCP(sport=self.src_port, dport=port, flags="AR"), verbose=0,
                                  timeout=1)
                    self.set_print(self.dst_ip, port, self.results[1])
                elif resp.getlayer(TCP).flags == 0x14:
                    self.set_print(self.dst_ip, port, self.results[2])


    def udp_scan(self):
        for port in [21, 23, 25, 53, 80, 110, 443]:
            resp = sr1(IP(dst=self.dst_ip) / UDP(sport=self.src_port, dport=port), timeout=2, verbose=0)
            if str(type(resp)) == "<type 'NoneType'>":
                retrans = []
                for count in range(0, 3):
                    retrans.append(
                        sr1(IP(dst=self.dst_ip) / UDP(sport=self.src_port, dport=port), timeout=2, verbose=0))
                for item in retrans:
                    if str(type(item)) != "<type 'NoneType'>":
                        self.udp_scan()
                self.set_print(self.dst_ip, port, self.results[1]+"|"+self.results[3])
            elif resp.haslayer(UDP):
                self.set_print(self.dst_ip, port, self.results[1])
            elif resp.haslayer(ICMP):
                if int(resp.getlayer(ICMP).type) == 3 and int(resp.getlayer(ICMP).code) == 3:
                    self.set_print(self.dst_ip, port, self.results[2])
                elif int(resp.getlayer(ICMP).type) == 3 and int(resp.getlayer(ICMP).code) in [1, 2, 9, 10, 13]:
                    self.set_print(self.dst_ip, port, self.results[3])
            else:
                print 'Checked'



    def ack_scan(self):
        for port in [21, 23, 25, 53, 80, 110, 443]:
            resp = sr1(IP(dst=self.dst_ip) / TCP(sport=self.src_port, dport=port, flags="A"), timeout=2, verbose=0)
            if str(type(resp)) == "<type 'NoneType'>":
                self.set_print(self.dst_ip, port, self.results[3])
            elif resp.haslayer(TCP):
                if resp.getlayer(TCP).flags == 0x4:
                    self.set_print(self.dst_ip, port, "Unfiltered)")
                elif resp.haslayer(ICMP):
                    if int(resp.getlayer(ICMP).type) == 3 and int(resp.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]:
                        self.set_print(self.dst_ip, port, self.results[3])

    def stealth_connection(self):
        for port in [21, 23, 25, 53, 80, 110, 443]:
            resp = sr1(IP(dst=self.dst_ip) / TCP(sport=self.src_port, dport=port, flags="S"), timeout=2, verbose=0)
            if str(type(resp)) == "<type 'NoneType'>":
                self.set_print(self.dst_ip, port, self.results[3])
            elif resp.haslayer(TCP):
                if resp.getlayer(TCP).flags == 0x12:
                    send_rst = sr(IP(dst=self.dst_ip) / TCP(sport=self.src_port, dport=port, flags="R"), verbose=0,
                                  timeout=1)
                    self.set_print(self.dst_ip, port, self.results[1])
                elif resp.getlayer(TCP).flags == 0x14:
                    self.set_print(self.dst_ip, port, self.results[2])
            elif resp.haslayer(ICMP):
                if int(resp.getlayer(ICMP).type) == 3 and int(resp.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]:
                    print self.set_print(self.dst_ip, port, self.results[3])


    def fin_scan(self):
        """
        Purpose: Send a fin packet over tcp, target should send back RST
        """
        for port in [21, 23, 25, 53, 80, 110, 443]:
            resp = sr1(IP(dst=self.dst_ip) / TCP(sport=self.src_port, dport=port, flags="F"), timeout=2, verbose=0)
            if str(type(resp)) == "<type 'NoneType'>":
                self.set_print(self.dst_ip, port, self.results[1]+"|"+self.results[3])
            elif resp.haslayer(TCP):
                if resp.getlayer(TCP).flags == 0x14:
                    self.set_print(self.dst_ip, port, self.results[2])
                elif resp.haslayer(ICMP):
                    if int(resp.getlayer(ICMP).type) == 3 and int(resp.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]:
                        self.set_print(self.dst_ip, port, self.results[3])


def main():
    sc = Scanner('localhost', '192.168.159.128')
    sc.tcp_scan()


if __name__ == '__main__':
    main()
