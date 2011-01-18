
import logging
import cymru
import cymru.ip2asn.dns
import cymru.mhr.dns

logging.basicConfig(level=logging.DEBUG)

cymru.ip2asn.dns.testAll()

cymru.mhr.dns.testAll()

