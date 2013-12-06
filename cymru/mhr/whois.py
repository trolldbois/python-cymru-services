#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+cymru@gmail.com
#
#
# This module is released under the GPL v3 License:
# http://www.opensource.org/licenses/gpl-3.0

import logging

from cymru.core.whois import WhoisClient as WhoisCoreClient

log = logging.getLogger('cymru.mhr.whois')


class mhr:
  def __init__(self, _hash=None, ts=None, detection=None ):
    self.ts    = ts
    self.detection    = detection
    if ( self.detection == 'NO_DATA'):
      self.detection = None
    self._hash    = _hash
  def __repr__(self):
    return "<%s instance: ts:%s|detection:%s%%|_hash:%s>" \
          % (self.__class__, self.ts, self.detection, self._hash)


class WhoisClient(WhoisCoreClient):
  '''Whois light client for Cymru Whois server.'''
  QTYPES=['MW']
  def __init__(self,server='hash.cymru.com',port=43,memcache_host='localhost:11211'):
    WhoisCoreClient.__init__(self,'mhr',server,port,memcache_host)
    
  def _getCB(self,qType):
    if qType == 'MW':
      return self.buildRequest,self.buildRecordMW
    else:
      pass

  def buildRequest(self,values):
    vstring = '\r\n'.join(values)
    vstring = 'begin\r\nverbose\r\n'+vstring+'\r\nend\r\n'
    return vstring

  def buildRecordMW(self,response):
    return self.buildRecords(response,mhr,0,'MW')

  def buildRecords(self,response,recordMaker,ind,qType):
    lines = response.split('\n')
    log.debug('lines : %s'%(lines))
    records = []
    for line in lines[2:-1]:
      columns = [col.strip() for col in line.split(' ')]
      log.debug('columns %s'%(columns))
      r = recordMaker(*columns)
      log.debug('caching : %s'%(r))
      self.cache.cache(columns[ind],r,qType)
      records.append(r)
    return records
  
