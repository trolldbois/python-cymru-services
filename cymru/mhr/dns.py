#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# cymrumhr.py
# Copyright (C) 2009 Loic Jaquemet loic.jaquemet+cymru@gmail.com
#
# This module is released under the GPL License v3 or higher

import hashlib 
import errno
import logging,sys

import ADNS,adns

log = logging.getLogger('CymruMHR')

try :
    import memcache
    HAVE_MEMCACHE = True
except ImportError:
    HAVE_MEMCACHE = False


def iterwindow(l, slice=50):
  """Generate sublists from an iterator
  >>> list(iterwindow(iter(range(10)),3))
  [[0, 1, 2], [3, 4, 5], [6, 7, 8], [9]]
  """
  assert(slice > 0)
  a=[]
  for x in l:
    if len(a) >= slice :
      yield a
      a=[]
    a.append(x)
  if a:
      yield a


class mhr:
  def __init__(self, ts=None, detection=None, _hash=None):
    self.ts    = ts
    self.detection    = detection
    self._hash    = _hash
  def __repr__(self):
    return "<%s instance: TS:%s|DETECTION:%s%%|HASH:%s>" \
          % (self.__class__, self.ts, self.antivir, self._hash)


class DNSClient:
  """Python interface to Malware Hash Registry

  **Usage**

  >>> from cymrumhr import DNSClient
  >>> c=DNSClient()
  >>> r=c.lookupFile("malware.file")
  15169
  >>> r=c.lookup(hash)
733a48a9cb49651d72fe824ca91e8d00.malware.hash.cymru.com descriptive text "1277221946 79"
  """
  sep=':'
  KEY_FMT = "cymrumhr:%s"
  MALWARE = 'MW'
  __ROOT = 'malware.hash.cymru.com.'
  client = None
  cacheip = None
  c = None
  
  def __init__(self, memcache_host='localhost:11211'):
    self.client=ADNS.init()
    self.cacheip=dict()
    self.c = None
    if HAVE_MEMCACHE and memcache_host:
      self.c = memcache.Client([memcache_host])
    else:
      self.c=dict()

  ''' return dict[ip] '''
  def get_cached(self, values, qType):
    log.debug('get_cached START values %s'%( values) )
    #print 'get_cached(ips) : self.c ==',self.c
    cached={}
    keys=[]
    if (not values):
      return {}
    keys = [self.KEY_FMT % (qType+":"+value) for value in values]
    if not HAVE_MEMCACHE:
      vals=dict()
      for k in keys:
        if ( k in self.c):
          vals[k] = self.c[k]
      log.debug('get_cached related vals in CACHE %s'%(vals) )
    else:
      vals = self.c.get_multi(keys)
    #
    prefixlen=len(self.KEY_FMT)+len(qType) -1
    log.debug('get_cached prefixlen  %d'%(prefixlen) )
    cached=dict(  (k[prefixlen:], v) for k,v in vals.items())
    if (not cached):
      cached={}
    # not cached is keys - vals.keys
    # build not_cached
    not_cached = [key[prefixlen:] for key in set(keys) - set(vals.keys()) ]
    log.debug('get_cached not_cached %s'%(not_cached) )
    return cached, not_cached

  def cache(self,value, r, qType):
    # caching the original IP and not the cidr network .. r.ip = cidr from asn
    if not HAVE_MEMCACHE:
      self.c[self.KEY_FMT % (qType+":"+value)]=r
    else:
      self.c.set(self.KEY_FMT % (qType+":"+value), r, 60*60*6)
    log.debug("cache '%s':'%s' "%((qType+":"+value),r))

  """
    Look up many values from type qType ( ORIGINm PEER, ASN ..)
    """
  def lookupmany(self, values, qType='MW'):
    # iterwindows on the request...
    if (len(values) == 0):
      yield 
      return
    batch=None
    #print values
    values = [str(value).strip() for value in values]
    for batch in iterwindow(values, 100):
      cached, not_cached = self.get_cached(batch,qType)
      log.debug("cached:%d not_cached:%d" % (len(cached), len(not_cached)) )
      if not_cached:
        for rec in self._lookupmany_raw(not_cached,qType):
          #print 'caching ', rec
          # To CHECK : sert a rien de cacher, on supplante le cache juste derriere...
          #cached[rec.ip] = rec
          pass
    log.debug("LOOKUP FINISHED")
    cached,not_cached = self.get_cached(batch,qType)
    log.debug("cached:%d not_cached:%d" % (len(cached), len(not_cached)) )
    #print cached
    #print not_cached
    for value in batch:
      if value in cached:
        yield cached[value]

    """Look up a single address.  """
  def lookup(self, value, qType='MW'):
    return list(self.lookupmany([value],qType))[0]
    
  def lookupmany_dict(self, hashes, qType='MW'):
    """Look up many hashes, returning a dictionary of hash -> record"""
    hashes = set(hashes)
    return dict((r._hash, r) for r in self.lookupmany(hashes,qType))

  ''' submits the queries to ADNS'''
  def _lookupmany_raw(self, values, qType):
    # decide what callbacks to use
    buildRequest, resolveCB=self._getCB(qType)
    #
    values = set(values)
    keys=[]
    for value in values:
      #build qname and send resolve
      extra=(qType,value)
      fqdn=buildRequest(value)
      log.debug('Lookup %s'%(fqdn))
      self.client.submit(fqdn,adns.rr.TXT, 0, resolveCB, extra)
    self.client.finish()
    records,not_cached=self.get_cached(values,qType)
    return records.itervalues()


  def _getCB(self,qType):
    if qType == None:
      pass
    elif qType == self.MALWARE:
      return self._makeRequestHash,self._asyncResolveHash
    else:
      pass
  
  def _makeRequestHash(self,hashval):
    return '.'.join([hashval,self.__ROOT])

  def _asyncResolve( self, recordMaker, answer, qname, rr, flags, extra):
    log.debug(' inputs : %s ; qname:%s rr:%s flags:%s l:%s'%(answer, qname, rr, flags, extra) )
    r=''
    qType,realq=extra
    log.debug('Real query : %s , qname : %s '%(realq,qname))
    if (len(answer[3])==0):
      log.debug('No lookup for %s'%(qname))
      r=mhr(_hash=qname.split('.')[0])
    else:
      result=answer[3][0][0]
      parts=result.split(" ")
      parts.append(qname.split('.')[0])
      r=recordMaker(*parts)
    self.cache(realq,r,qType)

  '''
    #(0, None, 1259120947, (('9003 | 78.155.128.0/19 | FR | ripencc | 2007-07-31',),)) 25.138.155.78.origin.asn.cymru.com. 16 0 None  
  '''
  def _asyncResolveHash( self, answer, qname, rr, flags, l):
    self._asyncResolve(mhr,answer,qname,rr,flags,l)



def lookup_stdin():
    from optparse import OptionParser
    hashtype='sha1'
    
    parser = OptionParser(usage = "usage: %prog [options] [files]")
    parser.add_option("-m", "--md5",  dest="md5", action="store_true", default='md5',
        help="use md5 hash")
    parser.add_option("-s", "--sha1", dest="sha1", action="store_true", default='sha1',
        help="use sha1 hash")

    if HAVE_MEMCACHE:
        parser.add_option("-c", "--cache", dest="cache", action="store", default="localhost:11211",
            help="memcache server (default localhost)")
        parser.add_option("-n", "--no-cache", dest="cache", action="store_false",
            help="don't use memcached")
    else:
        memcache_host = None

    (options, args) = parser.parse_args()

    if options.md5:
        hashtype = 'md5'
    else:
        hashtype = 'sha1'

    #setup the memcache option

    if HAVE_MEMCACHE:
        memcache_host = options.cache
        if memcache_host and ':' not in memcache_host:
            memcache_host += ":11211"

    if (len(args) < 2):
      log.error('Must provides files...')
      return

    c=DNSClient(memcache_host=memcache_host)
    hashes = []
    for filename in args:
      if hashtype == 'md5':
        h=hashlib.md5(file(filename, 'r').read()).hexdigest()
      elif hashtype == 'sha1': 
        h=hashlib.sha1(file(filename, 'r').read()).hexdigest()
      else:
        pass
      hashes.append(h)
    for r in c.lookupmany(hashes):
      print r


def testHash():
  c= DNSClient()
  hashes=['0fd453efa2320350f2b08fbfe194b39aab5f798d','733a48a9cb49651d72fe824ca91e8d00']
  #c.lookupFile("/tmp/malware")
  #733a48a9cb49651d72fe824ca91e8d00.malware.hash.cymru.com
  res=c.lookupmany(hashes)
  for r in res:
    print r
  res=c.lookupmany(hashes)
  for r in res:
    print r

if __name__ == "__main__":
  logging.basicConfig(level=logging.INFO)
  #testHash()
  lookup_stdin()

