__author__ = 'tal'

import urllib2


class OsType():
    def __init__(self, service_name, os, version):
        self.service_name = service_name
        self.os = os
        self.version = version


class BannerGrabber():
    def __init__(self, url):
        self.url = url
        self.os_dict = {'IIS 5.1': OsType('IIS 5.1', 'Windows', '2000')}

    def banner_grabber(self):
        try:
            u = urllib2.urlopen(self.url)
            return u.info()['server']
        except Exception, ex:
            print "Error!! ", ex.message
            return None

    def detect_os(self, server):
        print 'Os:%s %s' % (self.os_dict[server].os, self.os_dict[server].version)
