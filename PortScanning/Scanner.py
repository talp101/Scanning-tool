from scapy.layers.inet import TCP, IP, ICMP, UDP

__author__ = 'tal'
import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import socket


class Scanner():
    def __init__(self, dst_ip, src_ip, timeout, scan_type):
        print '******Starting port scanning******'
        self.dst_ip = socket.gethostbyname(dst_ip)
        # self.dst_ip = dst_ip
        self.src_ip = src_ip
        self.src_port = RandShort()
        self.timeout = int(timeout)
        self.scan_type = scan_type
        self.results = {1: "Open", 2: "Closed", 3: "Filtered"}

    def set_print(self, ip, port, state):
        print ip, ':', port, "- ", state

    def tcp_scan(self):
        print 'starting tcp_scan'
        for port in [21, 23, 25, 53, 80, 110, 443]:
            resp = sr1(IP(dst=self.dst_ip) / TCP(sport=self.src_port, dport=port, flags="S"), timeout=self.timeout,
                       verbose=0)
            if str(type(resp)) == "<type 'NoneType'>":
                self.set_print(self.dst_ip, port, self.results[2])
            elif resp.haslayer(TCP):
                if resp.getlayer(TCP).flags == 0x12:
                    send_rst = sr(IP(dst=self.dst_ip) / TCP(sport=self.src_port, dport=port, flags="AR"), verbose=0,
                                  timeout=self.timeout)
                    self.set_print(self.dst_ip, port, self.results[1])
                elif resp.getlayer(TCP).flags == 0x14:
                    self.set_print(self.dst_ip, port, self.results[2])

    def udp_scan(self):
        print 'starting udp_scan'
        for port in [21, 23, 25, 53, 80, 110, 443]:
            resp = sr1(IP(dst=self.dst_ip) / UDP(sport=self.src_port, dport=port), timeout=self.timeout, verbose=0)
            if str(type(resp)) == "<type 'NoneType'>":
                retrans = []
                for count in range(0, 3):
                    retrans.append(
                        sr1(IP(dst=self.dst_ip) / UDP(sport=self.src_port, dport=port), timeout=self.timeout,
                            verbose=0))
                for item in retrans:
                    if str(type(item)) != "<type 'NoneType'>":
                        self.udp_scan()
                self.set_print(self.dst_ip, port, self.results[1] + "|" + self.results[3])
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
        print 'starting ack_scan'
        for port in [21, 23, 25, 53, 80, 110, 443]:
            resp = sr1(IP(dst=self.dst_ip) / TCP(sport=self.src_port, dport=port, flags="A"), timeout=self.timeout,
                       verbose=0)
            if str(type(resp)) == "<type 'NoneType'>":
                self.set_print(self.dst_ip, port, self.results[3])
            elif resp.haslayer(TCP):
                if resp.getlayer(TCP).flags == 0x4:
                    self.set_print(self.dst_ip, port, "Unfiltered)")
                elif resp.haslayer(ICMP):
                    if int(resp.getlayer(ICMP).type) == 3 and int(resp.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]:
                        self.set_print(self.dst_ip, port, self.results[3])

    def stealth_connection(self):
        print 'starting stealth_connection'
        for port in [21, 23, 25, 53, 80, 110, 443]:
            resp = sr1(IP(dst=self.dst_ip) / TCP(sport=self.src_port, dport=port, flags="S"), timeout=self.timeout,
                       verbose=0)
            if str(type(resp)) == "<type 'NoneType'>":
                self.set_print(self.dst_ip, port, self.results[3])
            elif resp.haslayer(TCP):
                if resp.getlayer(TCP).flags == 0x12:
                    send_rst = sr(IP(dst=self.dst_ip) / TCP(sport=self.src_port, dport=port, flags="R"), verbose=0,
                                  timeout=self.timeout)
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
        print 'starting fin_scan'
        for port in [21, 23, 25, 53, 80, 110, 443]:
            resp = sr1(IP(dst=self.dst_ip) / TCP(sport=self.src_port, dport=port, flags="F"), timeout=self.timeout,
                       verbose=0)
            if str(type(resp)) == "<type 'NoneType'>":
                self.set_print(self.dst_ip, port, self.results[1] + "|" + self.results[3])
            elif resp.haslayer(TCP):
                if resp.getlayer(TCP).flags == 0x14:
                    self.set_print(self.dst_ip, port, self.results[2])
                elif resp.haslayer(ICMP):
                    if int(resp.getlayer(ICMP).type) == 3 and int(resp.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]:
                        self.set_print(self.dst_ip, port, self.results[3])

    def run_scan(self,):
        options = {'t': self.tcp_scan,
                   'u': self.udp_scan,
                   'a': self.ack_scan,
                   's': self.stealth_connection,
                   'f': self.fin_scan,
        }
        try:
            options[self.scan_type]()
        except Exception, ex:
            print '%s is not vaild scan_type, bye bye' % self.scan_type
            exit(1)
