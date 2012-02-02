#! /usr/bin/env python2
from __future__ import print_function

from io import BytesIO
from contextlib import closing
import elf
from gzip import GzipFile

MODULE_DIR = "lib/modules"

def open_elf(path):
    (payload, raw) = gzopen(path)
    with closing(raw):
        if payload is raw:
            file = elf.FileRef(path)
        else:
            file = Context(elf.File(BytesIO(payload.read())))
    with file:
        pass
    return file

def gzopen(path):
    raw = None
    try:
        raw = open(path, "rb")
        header = raw.read(2)
        raw.seek(0)
        if header == bytearray((31, 139)):
            return (GzipFile(fileobj=raw), raw)
        else:
            return (raw, raw)
    except:
        if raw is not None:
            raw.close()
        raise

class Context:
    """A dummy context manager that does nothing special"""
    def __init__(self, arg=None):
        self.arg = arg
    def __enter__(self):
        return self.arg
    def __exit__(self, *exc):
        pass
