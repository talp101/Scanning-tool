__author__ = 'tal'
#!/usr/bin/env python
import os, sys

sys.path.insert(0, os.path.abspath(".."))
import argparse

import BannerGrabbing.BannerGrabbing
import NetworkMapping.NetworkMapping
import Scanner.Scanner


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-ip', metavar="", help='ip target')
    parser.add_argument('-p', metavar="", help='protocol type UDP/TCP/ICMP')
    parser.add_argument('-type', metavar="", help='scan type, t-tcp, u-udp, a- ack, s - sealth, f- fin')
    parser.add_argument("-pl", metavar="", help="Port list e.g. 21,22,80")
    parser.add_argument('-t', metavar="", type=int, default=2, help='time interval default 2')
    parser.add_argument('-b', metavar="", type=int, default=1, help='1 turn on banner grabbing, 0 turn off')
    args = parser.parse_args()

    ports = []
    if args.pl:
        pl = (args.pl).split(',')
        ports += pl
    if args.b == 1 and args.p.upper() == 'ICMP':
        bn = BannerGrabbing.BannerGrabbing.BannerGrabber(args.ip)
        bn.detect_os()
        nm = NetworkMapping.NetworkMapping.NetworkMapping()
        nm.nm_run()
    elif args.b == 1 and (args.p.upper() == 'TCP' or args.p.upper() == 'UDP'):
        bn = BannerGrabbing.BannerGrabbing.BannerGrabber(args.ip)
        bn.detect_os()
        s = Scanner.Scanner.Scanner(args.ip, 'localhost', args.t, args.type, ports)
        s.run_scan()
    elif args.b == 0 and args.p.upper() == 'ICMP':
        nm = NetworkMapping.NetworkMapping.NetworkMapping()
        nm.nm_run()
    elif args.b == 0 and (args.p.upper() == 'TCP' or args.p.upper() == 'UDP'):
        s = Scanner.Scanner.Scanner(args.ip, 'localhost', args.t, args.type, ports)
        s.run_scan()
    else:
        print 'Error with args, bye bye'
        exit(1)
    print "Hope you enjoyed!!"


if __name__ == "__main__":
    main()