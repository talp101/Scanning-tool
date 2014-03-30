__author__ = 'tal'

import optparse
from PortScanning import scanner



def main():
    s = scanner.Scanner("82.166.60.130", "127.0.0.1")
    print "created s"
    s.tcp_scan()
    print "End"

if __name__ == "__main__":
    main()