import time
import logging

from dnslib.server import DNSServer
from resolver import *

handler = logging.StreamHandler()
handler.setLevel(logging.INFO)
handler.setFormatter(logging.Formatter('%(asctime)s: %(message)s', datefmt='%H:%M:%S'))

logger = logging.getLogger(__name__)
logger.addHandler(handler)
logger.setLevel(logging.INFO)

def main():
    resolver = DNSResolver("config.txt")
    
    port = 53
    udp_server = DNSServer(resolver, port=port)
    tcp_server = DNSServer(resolver, port=port, tcp=True)

    logger.info(f"Starting DNS server on port {port}")
    udp_server.start_thread()
    tcp_server.start_thread()

    try:
        while udp_server.isAlive():
            time.sleep(1)
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    main()