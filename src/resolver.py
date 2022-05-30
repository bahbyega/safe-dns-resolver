from dnslib import *

# currently supported record types for config file
TYPES = {
    "A": QTYPE.A,
    "NS": QTYPE.NS,
    "MX": QTYPE.MX,
    "CNAME": QTYPE.CNAME
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

class DNSResolver():

    def __init__(self, config_file):
        self.domain_filter = self.__load_config(config_file)
        self.domain_cache = {}

    def __load_config(self, config_file):
        if config_file.exist():
            print(f"Loading configuration file at {config_file}: ")
            domain_filter = {}

            with open(config_file, 'r') as config:
                for line in config:
                    line = line.rstrip('\n\t\r ')

                    host, type, data = line.split(maxsplit=2)

                    if type not in TYPES:
                        raise ValueError(f"Record type '{type}' is not supported.")                    

                    domain_filter[(host, type)] = RR(
                        rname=DNSLabel(host),
                        rtype=TYPES[type],
                        rclass=1,
                        rdata=data
                        ttl=3600
                    )

            return domain_filter
        
        else:
            raise FileNotFoundError(f"File '{config_file}' was not foung.")

    def __get_rr(self, q):
        if q in self.domain_filter:
            return self.domain_filter[q]

        elif q in self.domain_cache:
            return self.domain_cache[q]
        
        else:
            for root_server in ROOT_SERVERS:
                rr = self.send_request(root_server, q)
                self.domain_cache[q] = rr

                return rr
                
    def send_request(self, root_server, q):
        qname, qtype = q
        question = DNSRecord.question(qname, qtype)
        
        r_packet = question.send(root_server, 53)
        response = DNSRecord.parse(r_packet)


        if question.header.id != response.header.id:
            raise DNSError('Response transaction id does not match query transaction id')

        return response.rr


    def dns_reply(self, packet):
        request = DNSRecord.parse(packet)

        reply = DNSRecord(
            DNSHeader(
                id=request.header.id
                qr=1
                aa=1
                ra=1
            ),
            q=request.q
        )

        qname = request.q.qname
        qtype = request.q.qtype
        q = (qname, qtype)
        
        resource_record = self.__get_rr(q)
        reply.add_answer(resource_record)

        return reply.pack()

    def resolve(self, packet):
        reply = self.dns_reply(packet)
