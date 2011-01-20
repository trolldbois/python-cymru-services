import logging
import cymru.ip2asn.dns
import cymru.ip2asn.whois
import cymru.mhr.dns
import cymru.mhr.whois
import cymru.bogon.dns

logging.basicConfig(level=logging.INFO)

cymru.ip2asn.dns.testAll()
cymru.ip2asn.whois.testAll()
cymru.mhr.dns.testAll()
cymru.bogon.dns.testAll()
cymru.mhr.whois.testAll()

import sys
sys.exit()

'''
  Examples.
'''
import socket
from cymru.ip2asn.dns import DNSClient as ip2asn
client = ip2asn()

ip = socket.gethostbyname("www.google.com")
client.lookup(ip,qType='IP')
client.lookup('15169',qType='ASN')

ip6 = socket.getaddrinfo("www.nerim.net",80,socket.AF_INET6,0,0)[0][4][0]
client.lookup(ip6,qType='IP6')
client.lookupmany(['2001:4860:8010::68','2001:7a8:1:1::76'],qType='IP6')
client.lookupmany(['1515','5005'],qType='ASN')
client.lookup('91.121.224.117',qType='PEER')


import hashlib
from cymru.mhr.dns import DNSClient as mhr
client=mhr()
h=hashlib.sha1(file("/tmp/malware", 'r').read()).hexdigest()
#md5
client.lookup('733a48a9cb49651d72fe824ca91e8d00')
#sha1
client.lookup('0fd453efa2320350f2b08fbfe194b39aab5f798d')
from cymru.mhr.whois import WhoisClient as whois
client=whois()
#md5
client.lookup('733a48a9cb49651d72fe824ca91e8d00')
#sha1
client.lookup('0fd453efa2320350f2b08fbfe194b39aab5f798d')


from cymru.bogon.dns import DNSClient as bogon
client=bogon()
ips=['192.168.0.244','198.51.100.0','202.42.42.42']
client.lookupmany_dict(ips,'IP')
client.lookupmany_dict(ips,'FULLIP')
ip6s=['fe80::4','3ffe:5678:987::3','2001:678:67::01']
client.lookupmany_dict(ip6s,'FULLIP6')
client.lookupmany_dict(ip6s,'FULLIP6RANGE')

from cymru.ip2asn.whois import WhoisClient as whois
client=whois()
ips=['192.168.0.244','198.51.100.0','202.42.42.42']
client.lookupmany_dict(ips)
ip6s=['2001:4860:8010::68','2001:7a8:1:1::76']
client.lookupmany_dict(ip6s,qType='IP6')
client.lookupmany_dict(['1515','5005'],qType='ASN')



