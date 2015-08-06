from __future__ import division, absolute_import
import os
import sys
import time
import errno
import syslog
import signal
import logging
import argparse
import threading
from systemd import journal

from .converter import Converter


log = logging.getLogger(__name__)
cursor_path = '/var/lib/journal2gelf/cursor'
mark_message_id = '2a8d83d2eec744b4aa38d766915b3147'
cursor_save_interval = 60
thread_check_interval = 5


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
    parser.add_argument('-m', '--mark-interval', metavar='SECONDS', type=int,
                        help="write alive mark to journal every SECONDS, disabled by default")
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

    def sig_handler(*args):
        if conv.cursor:
            save_cursor(conv.cursor)
        sys.exit(0)

    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, sig_handler)

    threads = []

    def converter_thread():
        conv.run(args.merge, cursor)

    def cursor_thread():
        mkdir_p(os.path.dirname(cursor_path))
        last_saved = None
        while True:
            time.sleep(cursor_save_interval)
            c = conv.cursor
            if c != last_saved:
                save_cursor(c)
                last_saved = c

    t = threading.Thread(target=converter_thread, name='ConverterThread')
    t.daemon = True
    t.start()
    threads.append(t)

    t = threading.Thread(target=cursor_thread, name='CursorThread')
    t.daemon = True
    t.start()
    threads.append(t)

    if args.mark_interval:
        def mark_thread():
            while True:
                journal.send('-- MARK --', PRIORITY=syslog.LOG_INFO, MESSAGE_ID=mark_message_id)
                time.sleep(args.mark_interval)

        t = threading.Thread(target=mark_thread, name='MarkThread')
        t.daemon = True
        t.start()
        threads.append(t)

    while True:
        for t in threads:
            if not t.is_alive():
                save_cursor(conv.cursor)
                log.error('Thread %s is dead, exiting', t.name)
                sys.exit(1)
        time.sleep(thread_check_interval)


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
