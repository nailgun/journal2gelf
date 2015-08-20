from __future__ import division, absolute_import
from systemd import journal


class Reader(journal._Reader):
    def wait(self, timeout=None):
        us = -1 if timeout is None else int(timeout * 1000000)
        return super(Reader, self).wait(us)

    def __iter__(self):
        return self

    def __next__(self):
        rec = self.get_next()
        while not rec:
            self.wait()
            rec = self.get_next()
        return rec

    next = __next__

    def get_next(self, skip=1):
        if self._next(skip):
            entry = self._get_all()
            if entry:
                entry['__REALTIME_TIMESTAMP'] = self._get_realtime()
                entry['__MONOTONIC_TIMESTAMP'] = self._get_monotonic()
                entry['__CURSOR'] = self._get_cursor()
                return entry

    def get_previous(self, skip=1):
        return self.get_next(-skip)
