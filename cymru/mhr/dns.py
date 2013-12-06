#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+cymru@gmail.com
#
# This module is released under the GPL License v3 or higher

import hashlib 
import errno
import logging,sys

import adns

from cymru.core.dns import DNSClient as DNSCoreClient

log = logging.getLogger('cymru.mhr.dns')


class mhr:
  def __init__(self, ts=None, detection=None, _hash=None):
    self.ts    = ts
    self.detection    = detection
    self._hash    = _hash
  def __repr__(self):
    return "<%s instance: ts:%s|detection:%s%%|_hash:%s>" \
          % (self.__class__, self.ts, self.detection, self._hash)




class DNSClient(DNSCoreClient):
  """Python interface to Malware Hash Registry

  **Usage**

  >>> from cymrumhr import DNSClient
  >>> c=DNSClient()
  >>> r=c.lookupFile("malware.file")
  15169
  >>> r=c.lookup(hash)
733a48a9cb49651d72fe824ca91e8d00.malware.hash.cymru.com descriptive text "1277221946 79"
  """
  QTYPES=['MW']
  MALWARE = 'MW'
  __ROOT = 'malware.hash.cymru.com.'
  
  def __init__(self, memcache_host='localhost:11211'):
    DNSCoreClient.__init__(self,'mhr')
    pass

  def _getCB(self,qType):
    if qType == None:
      pass
    elif qType == self.MALWARE:
      return self._makeRequestHash,self._asyncResolveHash
    else:
      pass
  
  def _makeRequestHash(self,hashval):
    return adns.rr.TXT,'.'.join([hashval,self.__ROOT])

  def _asyncResolve( self, recordMaker, answer, qname, rr, flags, extra):
    log.debug(' inputs : %s ; qname:%s rr:%s flags:%s l:%s'%(answer, qname, rr, flags, extra) )
    r = None
    qType,realq=extra
    log.debug('Real query : %s , qname : %s '%(realq,qname))
    if (len(answer[3])==0):
      log.debug('No lookup for %s'%(qname))
      r = mhr(_hash=qname.split('.')[0])
    else:
      result = answer[3][0][0].decode()
      parts = result.split(" ")
      parts.append(qname.split('.')[0])
      r = recordMaker(*parts)
    self.cache.cache(realq,r,qType)

  '''
    #(0, None, 1259120947, (('9003 | 78.155.128.0/19 | FR | ripencc | 2007-07-31',),)) 25.138.155.78.origin.asn.cymru.com. 16 0 None  
  '''
  def _asyncResolveHash( self, answer, qname, rr, flags, l):
    self._asyncResolve(mhr,answer,qname,rr,flags,l)


