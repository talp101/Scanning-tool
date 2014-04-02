__author__ = 'tal'
import  ipcalc

class NetworkMapping():
    def __init__(self, subnet):
        self.subnet = ipcalc.Network(subnet)

    def subnet_calc(self):
        print 'The Servers are:'
        print self.subnet.network()
