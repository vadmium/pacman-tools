# Reference: https://www.sco.com/developers/gabi/latest/contents.html

from elf import Elf
from lib import Record
from os import environb
from os.path import (isabs, dirname)
from os import (readlink, listdir)
from stat import (S_ISUID, S_ISGID)
from contextlib import closing
from lib import strip
from os import path
import fnmatch
from collections import defaultdict

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
        
        for dir in cache.config_dirs:
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

class LibCache(object):
    def __init__(self, fs):
        self.fs = fs
        self.cached_dirs = dict()
        
        self.config_dirs = []
        self.config_parse(b"etc/ld.so.conf")
        self.config_dirs.extend((b"lib", b"usr/lib"))
    
    def search(self, dir, elf, lib):
        try:
            cache = self.cached_dirs[dir]
        except LookupError:
            #~ print("Searching object path", path)
            try:
                entries = self.fs.listdir(dir)
            except EnvironmentError:
                entries = []
            
            cache = Record(sonames=defaultdict(set), filenames=set())
            for filename in entries:
                try:
                    file = self.fs.open(path.join(dir, filename))
                except EnvironmentError:
                    continue
                with closing(file):
                    try:
                        probe = Elf(file)
                    except ValueError:
                        continue
                    if not elf.matches(probe):
                        continue
                    
                    cache.filenames.add(filename)
                    
                    dynamic = probe.read_segments().read_dynamic()
                    for soname in dynamic.soname:
                        soname = dynamic.read_str(soname)
                        cache.sonames[soname].add(filename)
            
            self.cached_dirs[dir] = cache
        
        return Record(
            soname=cache.sonames.get(lib, set()),
            filename=lib in cache.filenames,
        )
    
    def config_parse(self, name):
        """
        References:
        http://man7.org/linux/man-pages/man8/ldconfig.8.html
        http://www.daemon-systems.org/man/ld.so.conf.5.html
        """
        
        with closing(LdConfigFile(self.fs, name)) as file:
            while True:
                word = file.read_word()
                if not word:
                    break
                
                if word == b"include":
                    pattern = file.read_word()
                    if not pattern:
                        raise EOFError("include at EOF")
                    
                    try:
                        pattern = strip(pattern, b"/")
                    except ValueError:
                        pattern = path.join(dirname(name), pattern)
                    
                    for inc in self.fs.glob(pattern):
                        self.config_parse(inc)
                    continue
                
                try:
                    word = strip(word, b"/")
                except ValueError:
                    # BSD hardware dependent library directive line
                    file.skip_line()
                    continue
                
                self.config_dirs.append(word)

class LdConfigFile:
    def __init__(self, fs, name):
        self.file = fs.open(name)
        try:
            self.c = self.file.read(1)
        except:
            self.file.close()
            raise
    
    def read_word(self):
        while True:
            if self.c == b"#":
                self.c = self.file.read(1)
                self.skip_line()
            if not self.c or self.c not in self.SEPS:
                break
            
            self.c = self.file.read(1)
        
        word = bytearray()
        while self.c and self.c not in self.SEPS and self.c != b"#":
            word.extend(self.c)
            self.c = self.file.read(1)
        
        return bytes(word)
    
    def skip_line(self):
        while True:
            if not self.c or self.c in b"\r\n":
                break
            self.c = self.file.read(1)
    
    def close(self, *args, **kw):
        return self.file.close(*args, **kw)
    
    SEPS = b": \t\r\n,"

def is_privileged(mode):
    return mode & (S_ISUID | S_ISGID)

class Filesystem(object):
    def get_origin(self, path):
        return dirname(self.realpath(path))
    
    def glob(self, pattern):
        (dir, pattern) = path.split(pattern)
        for entry in fnmatch.filter(self.listdir(dir), pattern):
            yield path.join(dir, entry)
    
    def realpath(self, path):
        # Break the path into components. Working from the start out to the
        # filename, check if each component is a link. Each link expands to a
        # sub-path, and its components may require further expansion.
        
        # Stack of iterators of path components to expand. Each stack level
        # corresponds to the queue of unexpanded components of a link, or for
        # the top couple of levels, the queue for the supplied path.
        unexpanded = list()
        unexpanded.append(iter(path.split(b"/")))
        
        # Stack of each link name being expanded. If one of these is
        # referenced during expansion, we know there would be a loop.
        links = list()
        
        expanded = list()  # Fully expanded path components
        while unexpanded:
            while True:
                try:
                    component = next(unexpanded[-1])
                except StopIteration:
                    break
                if not component or component == b".":
                    continue
                if component == b"..":
                    if expanded:
                        expanded.pop()
                    continue
                
                expanded.append(component)
                subpath = b"/".join(expanded)
                
                if subpath in links:
                    # Loop detected: return the remaining path unexpanded
                    while unexpanded:
                        expanded.extend(unexpanded.pop())
                    return b"/".join(expanded)
                
                try:
                    target = self.readlink(subpath)
                except EnvironmentError:
                    # Not a link, does not exist at all, or some other error
                    pass
                else:
                    if isabs(target):
                        expanded = list()
                    else:
                        expanded.pop()
                    
                    links.append(subpath)
                    unexpanded.append(iter(target.split(b"/")))
            
            unexpanded.pop()
            if links:
                links.pop()
        return b"/".join(expanded)

class OsFilesystem(Filesystem):
    def open(self, path):
        return open(b"/" + path, "rb")
    def readlink(self, path):
        return readlink(b"/" + path)
    def listdir(self, path):
        return listdir(b"/" + path)

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
