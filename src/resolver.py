import os.path

import dns.message
import dns.query

from dnslib import A, QTYPE, NS, MX, CNAME
from dnslib import DNSLabel, RR
from dnslib.server import BaseResolver

from main import logger

# currently supported record types for config file
TYPES = {
    "A": (A, QTYPE.A)
}

ROOT_SERVERS = (
    "198.41.0.4",
    "199.9.14.201",
    "192.33.4.12",
    "199.7.91.13",
    "192.203.230.10",
    "192.5.5.241",
    "192.112.36.4",
    "198.97.190.53",
    "192.36.148.17",
    "192.58.128.30",
    "193.0.14.129",
    "199.7.83.42",
    "202.12.27.33"
)

class DNSResolver(BaseResolver):

    def __init__(self, config_file):
        super()
        self.domain_filter = self.__load_config(config_file)
        self.domain_cache = {}

    def __load_config(self, config_file):
        if os.path.exists(config_file):
            print(f"Loading configuration file at {config_file}: ")
            domain_filter = {}

            with open(config_file, 'r') as config:
                for line in config:
                    line = line.rstrip('\n\t\r ')

                    host, type, data = line.split(maxsplit=2)                

                    domain_filter[(DNSLabel(host), TYPES[type][1])] = RR(
                        rname=DNSLabel(host),
                        rtype=TYPES[type][1],
                        rdata=TYPES[type][0](str(data)),
                        ttl=3600
                    )

            print(f"Loaded {config_file}: ")

            return domain_filter
        
        else:
            raise FileNotFoundError(f"File '{config_file}' was not foung.")

    def algo(self, q):
        if q in self.domain_filter:
            return self.domain_filter[q]

        elif q in self.domain_cache:
            return self.domain_cache[q]
        
        else:
            for root_server in ROOT_SERVERS:
                qname, _ = q
                name = dns.name.from_text(str(qname))
                request = dns.message.make_query(name, dns.rdatatype.A)
                reply = self.ask_remote(request, root_server, q)

                for zones in reply.answer:
                    for zone in zones:
                        if zone.rdtype in [QTYPE.A]:
                            
                            rr = RR(
                                rname=DNSLabel(qname),
                                rtype=QTYPE.A,
                                rdata=A(str(zone)),
                                ttl=3600
                            )
                            self.domain_cache[(DNSLabel(qname), QTYPE.A)] = rr
                            
                            return rr
                        
                        else:
                            print("Unsupported type")

    
    def ask_remote(self, request, ip, q):
        qname, _ = q
        qname = dns.name.from_text(str(qname))
        response = dns.query.udp(request, ip)

        if response.answer:
            return response

        else:
            if response.additional:
                add_request = dns.message.make_query(qname, dns.rdatatype.A)
                
                i = 0
                while response.additional[i].rdtype != 1:
                    i += 1
                if response.additional[i].rdtype == 1:
                    return self.ask_remote(add_request, str(response.additional[i][0]), q)

            else:
                root_request = dns.message.make_query(str(response.authority[0][0]), dns.rdatatype.A)
                authority_ip = self.dig_ip(str(response.authority[0][0]), root_request, ip)
                auth_request = dns.message.make_query(qname, dns.rdatatype.A)

                return self.ask_remote(auth_request, str(authority_ip[0]), q)

    def dig_ip(self, auth_domain, request, ip):
        response = dns.query.udp(request, ip)
        
        if response.answer:
            return response.answer[0]

        else:
            if response.additional:
                additional_request = dns.message.make_query(auth_domain, dns.rdatatype.A)
                i = 0
                while response.additional[i].rdtype != 1:
                    i += 1

                if response.additional[i].rdtype == 1:

                    return self.dig_ip(auth_domain, additional_request, str(response.additional[i][0]))
            else:
                root_request = dns.message.make_query(str(response.authority[0][0]), dns.rdatatype.A)

                authority_ip = self.dig_ip(response.authority[0][0], root_request, ROOT_SERVERS[0])
                authority_request = dns.message.make_query(auth_domain, dns.rdatatype.A)
                
                return self.dig_ip(auth_domain, authority_request, str(authority_ip[0]))


    def resolve(self, request, handler):
        reply = request.reply()

        qname = reply.q.qname
        qtype = reply.q.qtype
        q = (qname, qtype)

        rr = self.algo(q)

        if rr:
            logger.info(f'Found record for {q}')
        else:
            logger.info('Error searching for record')
        
        reply.add_answer(rr)
        
        return reply