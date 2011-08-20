# Reference: https://www.sco.com/developers/gabi/latest/contents.html

from elf import Elf
from lib import Record
from os import environb

class Deps(object):
    def __init__(self, file, origin, privileged):
        self.elf = Elf(file)
        self.origin = Thunk(origin)
        self.privileged = privileged
        self.segments = self.elf.read_segments()
        self.dynamic = self.segments.read_dynamic()
    
    def interps(self):
        for seg in self.segments:
            if seg.type == seg.INTERP:
                yield seg.read_interp()
    
    def needed(self):
        for entry in self.dynamic.needed:
            entry = self.dynamic.read_str(entry)
            name = self.sub_origin(entry)
            yield Record(search=b"/" not in name, name=name, raw_name=entry)
    
    def search_dirs(self, deflibs):
        if not self.dynamic.runpath:
            for dirs in self.dynamic.rpath:
                dirs = self.dynamic.read_str(dirs)
                for dir in dirs.split(b":"):
                    yield dir.lstrip(b"/")
        
        if not self.privileged:
            try:
                search = environb[b"LD_LIBRARY_PATH"]
            except LookupError:
                pass
            else:
                for dirs in search.split(b";"):
                    for dir in dirs.split(b":"):
                        yield dir.lstrip(b"/")
        
        for dirs in self.dynamic.runpath:
            dirs = self.dynamic.read_str(dirs)
            for dir in dirs.split(b":"):
                try:
                    dir = self.sub_origin(dir)
                except ValueError:
                    pass
                else:
                    yield dir.lstrip(b"/")
        
        for dir in deflibs:
            yield dir
    
    def sub_origin(self, str):
        subs = (b"$ORIGIN", b"${ORIGIN}")
        if all(sub not in str for sub in subs):
            return str
        if self.privileged:
            raise ValueError("$ORIGIN substitution used "
                "for privileged executable: {0}".format(str.decode()))
        
        frags0 = str.split(subs[0])
        frags1 = []
        for f in frags0:
            frags1.extend(f.split(subs[1]))
        return self.origin().join(frags1)

import os
from os.path import (isabs, islink)

def realpath(path):
    if isinstance(path, bytes):
        sep = b'/'
        dot = b'.'
        dotdot = b'..'
        getcwd = os.getcwdb
    else:
        sep = '/'
        dot = '.'
        dotdot = '..'
        getcwd = os.getcwd
    root = sep
    
    # The path is broken into components. Each component may resolve to a
    # sub-path, and its components may require further resolution.
    
    # Stack of component iterators for each sub-path being resolved
    unres = [iter(path.split(sep))]
    if not isabs(path):
        unres.append(iter(getcwd().split(sep)))
    
    links = []  # Stack of links names of sub-paths being resolved
    resolved = []  # Fully resolved path components
    while unres:
        while True:
            try:
                component = next(unres[-1])
            except StopIteration:
                break
            if not component or component == dot:
                continue
            if component == dotdot:
                if resolved:
                    resolved.pop()
                continue
            
            resolved.append(component)
            dir = root + sep.join(resolved)
            if islink(dir):
                if dir in links:
                    while unres:
                        resolved.extend(unres.pop())
                    return root + sep.join(resolved)
                resolved.pop()
                links.append(dir)
                target = os.readlink(dir)
                unres.append(iter(target.split(sep)))
                if isabs(target):
                    resolved = []
        
        unres.pop()
        if links:
            links.pop()
    return root + sep.join(resolved)

class Thunk:
    def __init__(self, func, *args, **kw):
        self.func = func
        self.args = args
        self.kw = kw
        self.called = False
    
    def __call__(self):
        if self.called:
            return self.res
        
        self.res = self.func(*self.args, **self.kw)
        self.called = True
        del (self.func, self.args, self.kw)
        return self.res
