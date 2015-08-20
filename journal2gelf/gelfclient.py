from __future__ import division, absolute_import
import socket
import zlib
import json
import math
import struct
import logging
from datetime import datetime

from .exceptions import TooLongMessage

log = logging.getLogger(__name__)


# Based on https://github.com/orionvm/python-gelfclient
class UdpClient(object):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def __init__(self, host, port=12201, mtu=1450, source=None):
        assert mtu > 12

        # TODO: update address periodically
        addrinfo = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_DGRAM)[0]
        self.sockaddr = addrinfo[4]
        self.mtu = int(mtu)
        self.source = source if source else socket.gethostname()

    def chunks(self, data):
        chunk_size = self.mtu - 12  # leave space for GELF chunked header
        total_chunks = int(math.ceil(len(data) / float(chunk_size)))

        if total_chunks > 128:
            raise TooLongMessage('Chunks: {}'.format(total_chunks))

        count = 0
        message_id = hash(str(datetime.now().microsecond) + self.source)
        for i in xrange(0, len(data), chunk_size):
            header = struct.pack('!ccqBB', '\x1e', '\x0f', message_id, count, total_chunks)
            count += 1
            yield header + data[i:i+chunk_size]

    def log(self, **message):
        message.setdefault('version', '1.1')
        message.setdefault('short_message', '')
        if 'host' not in message:
            if 'source' in message:
                message['host'] = message['source']
            else:
                message['host'] = self.source

        message_json = json.dumps(message, separators=(',', ':'), ensure_ascii=False)
        output = zlib.compress(message_json)
        if len(output) > self.mtu:
            for chunk in self.chunks(output):
                self.sock.sendto(chunk, self.sockaddr)
        else:
            self.sock.sendto(output, self.sockaddr)
            
        return message
