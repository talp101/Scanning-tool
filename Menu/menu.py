__author__ = 'tal'

import optparse
from PortScanning import scanner



def main():
    s = scanner.Scanner("212.71.233.149", "127.0.0.1")
    print "created s"
    print s.dst_ip
    print s.src_port
    print s.src_ip
    s.tcp_scan()
    print "End"

if __name__ == "__main__":
    main()