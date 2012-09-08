import argparse
from time import sleep
import dns,dns.resolver,dns.query,dns.name,dns.zone
import uuid
from netaddr.ip import IPNetwork
import sys


DNS_SERVER = ['8.8.8.8']
DOMAIN = 'ibm.com'

class DNSRunner():
    #todo:add the mx records
    #todo:add ipv6 support
    def __init__(self,domainName,dnsServers=DNS_SERVER,tcp=False,soaBrute=False,findNeighbor=False):
        #the actual domain name to scan
        self._domainName = domainName.strip()
        self._tcp = tcp
        self._soaBrute = soaBrute
        self._findNeighbor = findNeighbor
        #a list of name servers. will be filled with the SOA ns servers.
        self._nsServers = []
        #Check if wildcard is enabled
        self._wildCard = False
        #if we found another subdomains they will be added to here
        self._domainsList = [self._domainName]
        self._resolver = dns.resolver.Resolver()
        #DNS server to use for resolving
        self._resolver.nameservers = []
        for i in dnsServers:
            self._resolver.nameservers.append(i.strip())
        if not len(self._resolver.nameservers):
            exit()
        self._soaList = []
        #list of possible subdomains
        self._subDomainsList = []
        #a dictionary of found sub domains
        self._foundDomains = {}
        self._subnetsList = []

    def run(self):
        if self._soaBrute:
            try:
                fd = open('soa.txt','r')
                for line in fd:
                    self._soaList.append(line.strip())
                fd.close()
            except IOError,e:
                print ('ERROR: Cant Open soa.txt')
        try:
            fd = open('hosts.txt','r')
            for line in fd:
                self._subDomainsList.append(line.strip())
            fd.close()
        except IOError,e:
            print ('ERROR: Cant Open hosts.txt')

        self._getNSServers()
        self._tryZoneTransffer()
        self._checkWildCard()
        if self._soaBrute:
            self._bruteForceSubDomainSOA()
        self._bruteForceSubDomains()
        self._extractSubnets()
        if self._findNeighbor:
            self._addClassCNeighbor()
        self._scanSubnets()
        self._dumpOutput()

    def _getNSServers(self):
        #TODO:if ns servers are in a diffrent SOA add it to the SOA list and add there ips to subnet scan!
        try:
            answers = list(self._resolver.query(self._domainName, 'NS',tcp=self._tcp))
            for ns in answers:
                self._nsServers.append(str(ns.target))
            print('Got NS Servers')
        except Exception,e:
            print('ERROR: Cant Get NS Servers %s'% e.message)

    def _tryZoneTransffer(self):
        for server in self._nsServers:
            try:
                zone = dns.zone.from_xfr(dns.query.xfr(server,self._domainName))
                print('Have Zone transfer, No need to continue')
                names = zone.nodes.keys()
                names.sort()
                for n in names:
                    print zone[n].to_text(n)
                #todo:save to file
                exit(0)
            except dns.exception.FormError, e:
                print('Cant Transfer the zone')

    def _checkWildCard(self):
        try:
            isItThere = self._resolver.query('%s.%s' % (uuid.uuid4().hex,self._domainName), 'A',tcp=self._tcp)
            for host in isItThere:
                self._wildCard = str(host)
        except dns.resolver.NXDOMAIN,e:
            print('No Wild Card')

    def _getSOA(self,preFix):
        try:
            answer = self._resolver.query('%s.%s' % (preFix,self._domainName), 'SOA',tcp=self._tcp)
            return True
        except dns.exception.DNSException,e:
            if isinstance(e,dns.resolver.NoAnswer):
                return True

            elif isinstance(e,dns.resolver.NXDOMAIN):
                pass

    def _checkPTR(self,ipAddr):
        try:
            addr = dns.reversename.from_address(ipAddr)
            ptrRec = str(self._resolver.query(addr,'PTR')[0])
            if ptrRec[-1:] == '.':
                return ptrRec[:-1]
            else:
                return ptrRec
        except Exception,e:
            return None

    def _bruteForceSubDomains(self):
        for domain in self._domainsList:
            counter = 0
            for subdomain in self._subDomainsList:
                counter += 1
                sys.stdout.write('\r%s/%s\r' % (counter,len(self._subDomainsList)))
                sys.stdout.flush()
                try:
                    answer = self._resolver.query('%s.%s' % (subdomain,domain), 'A',tcp=self._tcp)
                    if isinstance(answer.rrset,dns.rrset.RRset):
                        foundDomain = '%s.%s' % (subdomain,domain)
                        if len(answer.rrset.items) > 1:
                            self._foundDomains[foundDomain] = []
                            for ip in answer:
                                self._foundDomains[foundDomain].append(ip.address)
                                print('\rFound Domain %s --> %s' % (foundDomain ,ip.address))
                        else:
                            self._foundDomains[foundDomain] = [answer[0].address]
                            print('\rFound Domain %s --> %s' % (foundDomain,answer[0].address))

                except dns.resolver.NXDOMAIN,e:
                    pass
                except dns.resolver.NoAnswer, e:
                    print('\rERROR: NoAnswer on %s.%s' % (subdomain,domain))
                except dns.exception.Timeout,e:
                    print('ERROR: DNS Server Timeout, Sleeping for 10sec')
                    print('ERROR: Check domain %s.%s manualy' % (subdomain,domain))
                    sleep(10)

    def _bruteForceSubDomainSOA(self):
        counter = 0
        for line in self._soaList:
            counter += 1
            sys.stdout.write('\r%s/%s' % (counter,len(self._soaList)))
            if self._getSOA(line):
                self._domainsList.append(line)
                print('\rFound Possible SOA: %s' % line)
            else:
                print('\rNo SOA on %s' % line)

    def _extractSubnets(self):
        for foundDomain in self._foundDomains.iterkeys():
            for ip in self._foundDomains[foundDomain]:
                subnet = str(IPNetwork('%s/24' % ip).network)
                if subnet not in self._subnetsList:
                    self._subnetsList.append(subnet)
                    print('Found Subnet: %s/24' % subnet)

    def _addClassCNeighbor(self):
        neighbors = []
        for subnet in self._subnetsList:
            inc = self.incSubnet(subnet)
            dec = self.decSubnet(subnet)
            if inc:
                neighbors.append(inc)
            if dec:
                neighbors.append(dec)

        for subnet in neighbors:
            if subnet not in self._subnetsList:
                self._subnetsList.append(subnet)
                print('Added Neighbor %s' % subnet)

    def incSubnet(self,subnet):
        subnet = subnet.split('.')
        if subnet[2] == '256':
            return None
        subnet[2] = str(int(subnet[2])+1)
        subnet = '.'.join(subnet)
        return subnet

    def decSubnet(self,subnet):
        subnet = subnet.split('.')
        if subnet[2] == '0':
            return None
        subnet[2] = str(int(subnet[2])-1)
        subnet = '.'.join(subnet)
        return subnet

    def _scanSubnets(self):
        #todo:if found domain is in a different SOA add it to the SOA list and scan it
        counter = 0
        for subnet in self._subnetsList:
            counter += 1
            print('\rStarting Subnet Scan: %s (%s/%s)' % (subnet,counter,len(self._subnetsList)))
            networkCounter = 0
            for ip in IPNetwork('%s/24' % subnet):
                networkCounter += 1
                sys.stdout.write('\r%s/%s' % (networkCounter, len(IPNetwork('%s/24' % subnet))))
                ptrAnswer = self._checkPTR(ipAddr=str(ip))
                if ptrAnswer and self._domainName in ptrAnswer:
                    if self._foundDomains.has_key(ptrAnswer):
                        if str(ip) not in self._foundDomains[ptrAnswer]:
                            self._foundDomains[ptrAnswer].append(str(ip))
                            print('\rFound Domain %s --> %s' % (ptrAnswer,str(ip)))
                    else:
                        self._foundDomains[ptrAnswer] = list()
                        self._foundDomains[ptrAnswer].append(str(ip))
                        print('\rFound Domain %s --> %s' % (ptrAnswer,str(ip)))

    def _dumpOutput(self):
        #todo:Format output better
        fd = open('%s.txt' % self._domainName,'a')
        for foundDomain in self._foundDomains.iterkeys():
            for ip in self._foundDomains[foundDomain]:
                fd.write('%s --> %s\n' % (ip,foundDomain))
        fd.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(conflict_handler='resolve',description='This is a DNSRunner Beta')
    parser.add_argument('-d',action='store',dest='domainName')
    parser.add_argument('-a',action='store_true',dest='soaBrute')
    parser.add_argument('-n',action='store_true',dest='findNeighbor')
    parser.add_argument('-s',action='store',dest='dnsServer')
    parser.add_argument('-f',action='store',default='hosts.txt',dest='hostsFile')
    parser.add_argument('-t',action='store_true',dest='tcp')

    myArgs =  parser.parse_args(['-d google.com','-s 8.8.8.8,8.8.4.4'])

    runner = DNSRunner(myArgs.domainName,dnsServers=myArgs.dnsServer.split(','))
    runner.run()