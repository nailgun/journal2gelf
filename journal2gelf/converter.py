from __future__ import division, absolute_import
import json
import logging

from . import gelfclient
from .reader import Reader


log = logging.getLogger(__name__)
default_exclude_fields = frozenset([
    b'__MONOTONIC_TIMESTAMP',
    b'_MACHINE_ID',
    b'__CURSOR',
    b'_SYSTEMD_CGROUP',
    b'_AUDIT_SESSION',
    b'_CAP_EFFECTIVE',
    b'_SYSTEMD_SLICE',
    b'_AUDIT_LOGINUID',
    b'_SYSTEMD_OWNER_UID',
    b'_SOURCE_REALTIME_TIMESTAMP',
    b'_SYSTEMD_SESSION',
])


class Converter(object):
    def __init__(self, host, port, exclude_fields=set(), default_excludes=True):
        self.gelf = gelfclient.UdpClient(host, port=port)
        self.exclude_fields = set(exclude_fields)
        if default_excludes:
            self.exclude_fields.update(default_exclude_fields)
        self.debug = False
        self.send = True
        self.lower = True
        self.cursor = None

    def run(self, merge=False, cursor=None):
        j = Reader()

        try:
            j.next()
        except StopIteration:
            log.warning("Journal is empty. Or maybe you don't have permissions to read it.")
        finally:
            j.seek_head()

        if merge:
            if cursor:
                j.seek_cursor(cursor)
                try:
                    j.next()
                except StopIteration:
                    # cursor not found, journal was rotated
                    j.seek_head()
        else:
            j.seek_tail()
            j.get_previous()

        for record in j:
            self.cursor = record['__CURSOR']
            record = convert_record(record, excludes=self.exclude_fields, lower=self.lower)
            if self.send:
                self.gelf.log(**record)
            if self.debug:
                print json.dumps(record, indent=2)


# See https://www.graylog.org/resources/gelf-2/#specs
# And http://www.freedesktop.org/software/systemd/man/systemd.journal-fields.html
def convert_record(src, excludes=set(), lower=True):
    for k, v in src.iteritems():
        conv = field_converters.get(k)
        if conv:
            try:
                src[k] = conv(v)
            except ValueError:
                pass

    dst = {
        b'version': b'1.1',
        b'host': src.pop(b'_HOSTNAME', None),
        b'short_message': src.pop(b'MESSAGE', None),
        b'timestamp': src.pop(b'__REALTIME_TIMESTAMP', None),
        b'level': src.pop(b'PRIORITY', None),
        b'_facility': src.get(b'SYSLOG_IDENTIFIER') or src.get(b'_COMM')
    }

    for k, v in src.iteritems():
        if k in excludes:
            continue
        if lower:
            k = k.lower()
        if k in system_fields:
            k = b'_'+k
        dst[b'_'+k] = v

    return dst


def convert_timestamp(value):
    return float(value) / 1000000.0


def convert_monotonic_timestamp(value):
    try:
        return convert_timestamp(value[0])
    except:
        raise ValueError


field_converters = {
    b'__MONOTONIC_TIMESTAMP': convert_monotonic_timestamp,
    b'EXIT_STATUS': int,
    b'_AUDIT_LOGINUID': int,
    b'_PID': int,
    b'COREDUMP_UID': int,
    b'COREDUMP_SESSION': int,
    b'SESSION_ID': int,
    b'_SOURCE_REALTIME_TIMESTAMP': convert_timestamp,
    b'_GID': int,
    b'INITRD_USEC': int,
    b'ERRNO': int,
    b'SYSLOG_FACILITY': int,
    b'__REALTIME_TIMESTAMP': convert_timestamp,
    b'_SYSTEMD_SESSION': int,
    b'_SYSTEMD_OWNER_UID': int,
    b'COREDUMP_PID': int,
    b'_AUDIT_SESSION': int,
    b'USERSPACE_USEC': int,
    b'PRIORITY': int,
    b'KERNEL_USEC': int,
    b'_UID': int,
    b'SYSLOG_PID': int,
    b'COREDUMP_SIGNAL': int,
    b'COREDUMP_GID': int,
    b'_SOURCE_MONOTONIC_TIMESTAMP': convert_monotonic_timestamp,
    b'LEADER': int,
    b'CODE_LINE': int
}

system_fields = frozenset([
    b'_id',   # actually only _id and _uid are reserved in elasticsearch
    b'_uid',  # but for consistency we rename all this fields
    b'_gid',
    b'_pid',
])
