#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+cymru@gmail.com
#
# This module is released under the GPL License v3 or higher

import errno
import logging,sys

import adns,IPy

from ..core.dns import DNSClient as DNSCoreClient

log = logging.getLogger('cymru:bogon:dns')


class DNSClient(DNSCoreClient):
  """Python interface to Bogon service

  **Usage**

  >>> from cymrumhr import DNSClient
  >>> c=DNSClient()
  >>> r=c.lookupFile("malware.file")
  15169
  >>> r=c.lookup(hash)
733a48a9cb49651d72fe824ca91e8d00.malware.hash.cymru.com descriptive text "1277221946 79"
  """
  QTYPES=['IP','FULLIP','FULLIPRANGE','FULLIP6','FULLIP6RANGE']
  IP_BOGON = 'IP'
  IP_BOGON_ROOT = '.bogons.cymru.com.'
  FULLIP_BOGON = 'FULLIP'
  FULLIPRANGE_BOGON = 'FULLIPRANGE'
  FULLIP_BOGON_ROOT = '.v4.fullbogons.cymru.com.'
  FULLIP6_BOGON = 'FULLIP6'
  FULLIP6RANGE_BOGON = 'FULLIP6RANGE'
  FULLIP6_BOGON_ROOT = '.v6.fullbogons.cymru.com.'
  
  def __init__(self, memcache_host='localhost:11211'):
    DNSCoreClient.__init__(self,'bogon')
    pass

  def _getCB(self,qType):
    if qType == None:
      pass
    elif qType == self.IP_BOGON:
      return self._makeRequestIP,self._asyncResolve
    elif qType == self.FULLIP_BOGON:
      return self._makeRequestFullIP,self._asyncResolve
    elif qType == self.FULLIPRANGE_BOGON:
      return self._makeRequestFullIPRange,self._asyncResolveRange
    elif qType == self.FULLIP6_BOGON:
      return self._makeRequestFullIP6,self._asyncResolve
    elif qType == self.FULLIP6RANGE_BOGON:
      return self._makeRequestFullIP6Range,self._asyncResolveRange
    else:
      pass
              
  def _makeRequestIP(self,ip):
    return adns.rr.A,IPy.IP(ip).reverseName().replace('.in-addr.arpa.',self.IP_BOGON_ROOT)
  def _makeRequestFullIP(self,ip):
    return adns.rr.A,IPy.IP(ip).reverseName().replace('.in-addr.arpa.',self.FULLIP_BOGON_ROOT)
  def _makeRequestFullIPRange(self,ip):
    return adns.rr.TXT,IPy.IP(ip).reverseName().replace('.in-addr.arpa.',self.FULLIP_BOGON_ROOT)
  def _makeRequestFullIP6(self,ip):
    return adns.rr.A,IPy.IP(ip).reverseName().replace('.ip6.arpa.',self.FULLIP6_BOGON_ROOT)
  def _makeRequestFullIP6Range(self,ip):
    return adns.rr.TXT,IPy.IP(ip).reverseName().replace('.ip6.arpa.',self.FULLIP6_BOGON_ROOT)

  def _asyncResolve( self, answer, qname, rr, flags, extra):
    log.debug(' inputs : %s ; qname:%s rr:%s flags:%s l:%s'%(answer, qname, rr, flags, extra) )
    r=''
    qType,realq=extra
    log.debug('Real query : %s , qname : %s '%(realq,qname))
    if (len(answer[3])==0):
      # it's not a bogon
      log.debug('No lookup for %s'%(qname))
      r=False
    else:
      # it's a bogon
      r=True
    self.cache.cache(realq,r,qType)

  def _asyncResolveRange( self, answer, qname, rr, flags, extra):
    log.debug(' inputs : %s ; qname:%s rr:%s flags:%s l:%s'%(answer, qname, rr, flags, extra) )
    r=''
    qType,realq=extra
    log.debug('Real query : %s , qname : %s '%(realq,qname))
    if (len(answer[3])==0):
      # it's not a bogon
      log.debug('No lookup for %s'%(qname))
      r=False
    else:
      # it's a bogon
      r=IPy.IP(answer[3][0][0])
    self.cache.cache(realq,r,qType)


def testBogon():
  log.debug('START TEST BOGON')
  c= DNSClient()
  ips=['192.168.0.244','198.51.100.0','202.42.42.42']
  datas=c.lookupmany_dict(ips,'IP')
  for ip in ips:
    log.info("c.lookupmany_dict(%s,'IP') = %s"%(ip,datas[ip]))
  log.debug('STOP TEST BOGON\n\n')

def testFullBogon():
  log.debug('START TEST FULLBOGON')
  c= DNSClient()
  ips=['192.168.0.244','198.51.100.0','202.42.42.42']
  datas=c.lookupmany_dict(ips,'FULLIP')
  for ip in ips:
    log.info("c.lookupmany_dict(%s,'FULLIP') = %s"%(ip,datas[ip]))
  log.debug('STOP TEST FullBOGON\n\n')

def testFullBogonRange():
  log.debug('START TEST FULLBOGONRANGE')
  c= DNSClient()
  ips=['192.168.0.244','198.51.100.0','202.42.42.42']
  datas=c.lookupmany_dict(ips,'FULLIPRANGE')
  for ip in ips:
    log.info("c.lookupmany_dict(%s,'FULLIPRANGE') = %s"%(ip,datas[ip]))
  log.debug('STOP TEST FullBOGONRANGE\n\n')

def testFull6Bogon():
  log.debug('START TEST FULLBOGON IPv6')
  c= DNSClient()
  ips=['fe80::4','3ffe:5678:987::3','2001:678:67::01']
  datas=c.lookupmany_dict(ips,'FULLIP6')
  for ip in ips:
    log.info("c.lookupmany_dict(%s,'FULLIP6') = %s"%(ip,datas[ip]))
  log.debug('STOP TEST FullBOGON IPv6\n\n')

def testFull6BogonRange():
  log.debug('START TEST FULLBOGON IPv6 RANGE')
  c= DNSClient()
  ips=['fe80::4','3ffe:5678:987::3','2001:678:67::01']
  datas=c.lookupmany_dict(ips,'FULLIP6RANGE')
  for ip in ips:
    log.info("c.lookupmany_dict(%s,'FULLIP6RANGE') = %s"%(ip,datas[ip]))
  log.debug('STOP TEST FullBOGON IPv6 RANGE\n\n')

def testAll():
  logging.basicConfig(level=logging.DEBUG)
  testBogon()
  testFullBogon()
  testFullBogonRange()
  testFull6Bogon()
  testFull6BogonRange()

