import timeit

__author__ = 'tal'

import urllib2


class OsType():
    def __init__(self, service_name, os, version):
        self.service_name = service_name
        self.os = os
        self.version = version


class BannerGrabber():
    def __init__(self, url):
        print "****** Starting Banner Grabbing ******"
        self.url = url
        if 'http://' not in self.url:
            self.url = "http://" + url
        self.os_dict = {'Microsoft-IIS/5.0': OsType('Microsoft-IIS/5.0', 'Windows', '2000'),
                        'nginx': OsType('nginx', 'Mac', 'OSX'),
                        'Microsoft-IIS/1.0': OsType('Microsoft-IIS/1.0', 'Windows', 'NT 3.51'),
                        'Microsoft-IIS/7.0': OsType('Microsoft-IIS/7.0', 'Windows', 'Server 2008'),
                        'Microsoft-IIS/7.5': OsType('Microsoft-IIS/7.5', 'Windows', 'Server 2008 R2'),
                        'Microsoft-IIS/8.0': OsType('Microsoft-IIS/8.0', 'Windows', 'Server 2012'),
                        'Microsoft-IIS/8.1': OsType('Microsoft-IIS/8.1', 'Windows', 'Server 2012 R2'),
                        'Apache': OsType('Apache', 'Unix', 'Ubuntu'),
                        'AkamaiGHost': OsType('AkamaiGHost', 'Linux', '2'),
                        'gws': OsType('gws', 'Google', 'Web Server'),
                        'Apache/2.2.22 (Ubuntu)': OsType('Apache/2.2.22 (Ubuntu)', 'Unix', 'Ubuntu'),
        }

    def banner_grabber(self):
        try:
            u = urllib2.urlopen(self.url)
            return u.info()['server']
        except Exception, ex:
            raise Exception('Could not connect to url')


    def detect_os(self, ):
        try:
            start = timeit.default_timer()
            server = self.banner_grabber()
            print 'Os:%s %s' % (self.os_dict[server].os, self.os_dict[server].version)
            print
            print "****** End Of Banner Grabbing ******"
            print "Banner Grabbing Took:" , timeit.default_timer() - start
        except Exception, ex:
            print "Can't get Server from this url"
            exit(1)


