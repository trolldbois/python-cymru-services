
import logging
import cymru
import cymru.ip2asn.dns
import cymru.mhr.dns
import cymru.bogon.dns

logging.basicConfig(level=logging.INFO)

cymru.ip2asn.dns.testAll()

cymru.mhr.dns.testAll()

cymru.bogon.dns.testAll()

