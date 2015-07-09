from __future__ import print_function, division, absolute_import, unicode_literals


class GelfException(Exception):
    pass


class TooLongMessage(GelfException):
    pass
