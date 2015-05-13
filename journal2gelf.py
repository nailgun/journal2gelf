#!/usr/bin/env python
from __future__ import division, absolute_import

import os
import sys
import time
import json
import errno
import signal
import logging
import argparse
import threading

import gelfclient
from systemd import journal

log = logging.getLogger('journal2gelf')
cursor_path = '/var/lib/journal2gelf/cursor'
cursor_save_interval = 60
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
    b'_SYSTEMD_SESSION'
])


def main():
    logging.basicConfig(format='%(message)s')

    parser = argparse.ArgumentParser(description="Export structured log records from the systemd journal and "
                                                 "send them to a Graylog2 server as GELF messages.")
    parser.add_argument('target', nargs=1,
                        help="graylog2 server host:port (UDP)")
    parser.add_argument('-e', '--exclude', metavar='FIELD', action='append', default=[],
                        help="exclude journal field FIELD")
    parser.add_argument('-E', '--no-defaults', action='store_true',
                        help="don't exclude fields, excluded by default")
    parser.add_argument('-u', '--uppercase', action='store_true',
                        help="don't lower field names in output")
    parser.add_argument('--debug', action='store_true',
                        help="print GELF jsons to stdout")
    parser.add_argument('--merge', action='store_true',
                        help="send unsent records at first")
    parser.add_argument('--dry-run', action='store_true',
                        help="don't send anything to graylog")
    args = parser.parse_args()

    try:
        host, port = args.target[0].rsplit(':', 1)
        port = int(port)
    except ValueError:
        parser.error('target must be in form host:port')
        return

    conv = Converter(host, port, args.exclude, not args.no_defaults)
    conv.debug = args.debug
    conv.send = not args.dry_run
    conv.lower = not args.uppercase

    cursor = load_cursor()

    def converter_thread():
        conv.run(args.merge, cursor)

    t = threading.Thread(target=converter_thread, name='ConverterThread')
    t.daemon = True
    t.start()

    def sig_handler(*a):
        if conv.cursor:
            save_cursor(conv.cursor)
        sys.exit(0)

    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, sig_handler)

    cursor_thread(conv)


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
        j = journal.Reader(converters=field_converters)

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

        for record in read_journal(j):
            self.cursor = record['__CURSOR']
            record = convert_record(record, excludes=self.exclude_fields, lower=self.lower)
            if self.send:
                self.gelf.log(record)
            if self.debug:
                print json.dumps(record, indent=2)


def read_journal(j):
    while True:
        j.wait()
        for record in j:
            yield record


# See https://www.graylog.org/resources/gelf-2/#specs
# And http://www.freedesktop.org/software/systemd/man/systemd.journal-fields.html
def convert_record(src, excludes=set(), lower=True):
    dst = {
        'version': '1.1',
        'host': src.pop(b'_HOSTNAME', None),
        'short_message': src.pop(b'MESSAGE', None),
        'timestamp': src.pop(b'__REALTIME_TIMESTAMP', None),
        'level': src.pop(b'PRIORITY', None),
        '_facility': src.get(b'SYSLOG_IDENTIFIER') or src.get(b'_COMM')
    }

    for k, v in src.iteritems():
        if k in excludes:
            continue
        if lower:
            k = k.lower()
        dst['_'+k] = v

    return dst


def convert_timestamp(value):
    return float(value) / 1000000.0


def convert_monotonic_timestamp(value):
    try:
        return convert_timestamp(value[0])
    except:
        raise ValueError


field_converters = {
    b'_BOOT_ID': unicode,
    b'__MONOTONIC_TIMESTAMP': convert_monotonic_timestamp,
    b'COREDUMP': unicode,
    b'EXIT_STATUS': int,
    b'_AUDIT_LOGINUID': int,
    b'_MACHINE_ID': unicode,
    b'_PID': int,
    b'COREDUMP_UID': int,
    b'COREDUMP_SESSION': int,
    b'SESSION_ID': int,
    b'_SOURCE_REALTIME_TIMESTAMP': convert_timestamp,
    b'__CURSOR': unicode,
    b'_GID': int,
    b'INITRD_USEC': int,
    b'MESSAGE_ID': unicode,
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
    b'COREDUMP_TIMESTAMP': unicode,
    b'LEADER': int,
    b'CODE_LINE': int
}


def cursor_thread(conv):
    mkdir_p(os.path.dirname(cursor_path))

    last_saved = None
    while True:
        time.sleep(cursor_save_interval)
        if conv.cursor != last_saved:
            save_cursor(conv.cursor)


def save_cursor(cursor):
    try:
        file(cursor_path, 'w').write(cursor)
    except:
        log.exception('Failed to save cursor:')


def load_cursor():
    try:
        return file(cursor_path, 'r').read()
    except IOError:
        return None


# http://stackoverflow.com/questions/600268/mkdir-p-functionality-in-python
def mkdir_p(path):
    try:
        os.makedirs(path)
    except OSError as e:
        if e.errno == errno.EEXIST and os.path.isdir(path):
            pass
        else:
            raise


if __name__ == '__main__':
    main()
