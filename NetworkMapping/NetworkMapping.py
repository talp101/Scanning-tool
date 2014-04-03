__author__ = 'tal'
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *



class NetworkMapping():
    def __init__(self,):
        print 'Starting NetWorkMapping On Your Subnet'

    def subnet_calc(self, net, interface):
        ans, unans = scapy.layers.l2.arping(net, iface=interface, timeout=1, verbose=1)
        for s, r in ans.res:
            line = r.sprintf("%Ether.src % %ARP.psrc%")
            try:
                hostname = socket.gethostbyaddr(r.psrc)
                line += " " + hostname[0]
            except socket.error:
                pass

    def long2net(self, arg):
        if arg <= 0 or arg >= 0xFFFFFFFF:
            raise ValueError("illegal netmask value", hex(arg))
        return 32 - int(round(math.log(0xFFFFFFFF - arg, 2)))

    def to_CIDR_notation(self, bytes_network, bytes_netmask):
        network = scapy.utils.ltoa(bytes_network)
        netmask = self.long2net(bytes_netmask)
        net = "%s/%s" % (network, netmask)
        if netmask < 16:
            print "%s is too big. skipping" % net
            return None
        return net

    def nm_run(self):
         for network, netmask, _, interface, address in scapy.config.conf.route.routes:

            # skip loopback network and default gw
            if network == 0 or interface == 'lo' or address == '127.0.0.1' or address == '0.0.0.0':
                continue

            if netmask <= 0 or netmask == 0xFFFFFFFF:
                continue

            net = self.to_CIDR_notation(network, netmask)

            if interface != scapy.config.conf.iface:
                # see http://trac.secdev.org/scapy/ticket/537
                print "skipping %s because scapy currently doesn't support arping on non-primary network interfaces" % net
                continue

            if net:
                self.subnet_calc(net, interface)



