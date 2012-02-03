#! /usr/bin/env python2
from __future__ import print_function

from io import BytesIO
import elf
from gzip import GzipFile
import os
from lib import (transplant, SEEK_CUR)
from collections import defaultdict
import struct
from os.path import commonprefix
from os.path import basename
from lib import Record
from lib import strip

MODULE_DIR = "lib/modules"

# This function, and some of the functions it calls, are based on "depmod"
# from "module-init-tools" (apparently GPL 2)
def depmod(basedir, kver):
    """Only generates the following files (the real "depmod" generates other
    files as well)
        modules.dep
        modules.dep.bin
        modules.alias.bin
        modules.symbols.bin
    """
    
    INDEX_PRIORITY_MIN = ~(~0 << 32)
    
    verify_version(kver)
    
    dirname = os.path.join(basedir, MODULE_DIR, kver)
    print("Scanning modules in", dirname)
    module_files = dict()
    for (dirpath, dirnames, filenames) in os.walk(dirname, followlinks=True):
        #~ print("Scanning", dirpath)
        for f in filenames:
            if not f.endswith((".ko", ".ko.gz")):
                continue
            
            fullpath = os.path.join(dirpath, f)
            pathname = transplant(fullpath, dirname)
            module_files.setdefault(f, Record(
                elf=open_elf(fullpath),
                pathname=pathname,
                order=INDEX_PRIORITY_MIN),
            )
        
        i = 0
        while i < len(dirnames):
            if dirnames[i] in ("source", "build"):
                del dirnames[i]
            else:
                i = i + 1
    
    print('Ordering modules by "modules.order"')
    module_paths = dict((mod.pathname, mod) for mod in module_files.values())
    
    tlist = list()
    file_name = os.path.join(dirname, "modules.order")
    if os.path.exists(file_name):
        with open(file_name, "r") as modorder:
            for (linenum, line) in enumerate(modorder, 1):
                try:
                    mod = module_paths.pop(line)
                except LookupError:
                    continue
                
                mod.order = linenum
                tlist.append(mod)
    tlist.extend(module_paths.values())
    
    print("Reading symbols from modules")
    symbol_owners = defaultdict(list)
    for (i, mod) in enumerate(tlist):
        print("{0}/{1}".format(i, len(tlist)), end="\r")
        with mod.elf as file:
            for sym in file.get_strings(b"__ksymtab_strings"):
                symbol_owners[sym].append(mod)
            
            strings = file.get_section(b".strtab")
            syms = file.get_section(b".symtab")
            if strings is not None and syms is not None:
                tables = dict.fromkeys((
                    b"pci", b"usb", b"ccw", b"ieee1394", b"pnp", b"pnp_card",
                    b"input", b"serio", b"of",
                ))
                
                for sym in file.symtab_entries(syms):
                    name = file.read_str(strings, sym.name)
                    try:
                        name = strip(name, b"__mod_", b"_device_table")
                    except ValueError:
                        continue
                    if name not in tables or tables[name] is not None:
                        continue
                    
                    file.file.seek(
                        file.shoff + file.shentsize * sym.shndx + 4)
                    if file.read("L") == (file.SHT_NOBITS,):
                        continue
                    
                    file.file.seek(+file.class_size + file.class_size,
                        SEEK_CUR)
                    (offset,) = file.read(file.class_type)
                    tables[name] = offset + sym.value
    print("{0}/{0}".format(len(tlist)))
    
    print("Reading dependencies of modules")
    for (i, mod) in enumerate(tlist):
        print("{0}/{1}".format(i, len(tlist)), end="\r")
        mod.deps = set()
        with mod.elf as file:
            strings = file.get_section(b".strtab")
            syms = file.get_section(b".symtab")
            if strings is None or syms is None:
                print('{0}: no ".strtab" or ".symtab"'.format(mod.pathname))
                continue
            
            sparc = file.machine in (file.EM_SPARC, file.EM_SPARCV9)
            for sym in file.symtab_entries(syms):
                if (sym.shndx != file.SHN_UNDEF or
                sparc and sym.type == file.STT_SPARC_REGISTER):
                    continue
                
                name = file.read_str(strings, sym.name)
                try:
                    lookup = strip(name, b".")
                except ValueError:
                    lookup = name
                
                try:
                    # Original "depmod" places later modules at front of hash
                    # table chain, so take latest module here
                    owner = symbol_owners[lookup][-1]
                except LookupError:
                    continue
                
                #~ print('{0} needs "{1}": {2}'.format(mod.pathname, name,
                    #~ owner.pathname))
                mod.deps.add(owner)
    print("{0}/{0}".format(len(tlist)))
    
    deps_index = Index()
    print('Generating "modules.dep"')
    with open(os.path.join(dirname, "modules.dep"), "w") as file:
        for (i, mod) in enumerate(tlist):
            print("{0}/{1}".format(i, len(tlist)), end="\r")
            
            dfs_steps = list()
            ancestors = set()
            visited = set()
            postorder = list()
            
            node = mod
            while True:
                dfs_steps.append(Record(
                    node=node, queue=iter(node.deps)))
                ancestors.add(node)
                
                while dfs_steps:
                    current = dfs_steps[-1]
                    try:
                        node = next(current.queue)
                    except StopIteration:
                        node = current.node
                        ancestors.remove(node)
                        visited.add(node)
                        postorder.append(node)
                        dfs_steps.pop()
                    else:
                        if node in ancestors:
                            print("{0}: Ignoring cyclic dependency of {1} "
                                "on {2}".format(mod.pathname,
                                current.mod.pathname, dep.pathname))
                            continue
                        if node in visited:
                            continue
                        break
                
                if not dfs_steps:
                    break
            
            line = mod.pathname + ":"
            if mod.deps:
                line += " " + " ".join(dep.pathname
                    for dep in reversed(postorder[:-1]))
            file.write(line)
            file.write("\n")
            
            deps_index.add(modname(mod.pathname), line.encode("ASCII"),
                mod.order)
    
    print('Writing "modules.dep.bin"')
    deps_index.write(dirname, "modules.dep.bin")
    
    print('Generating "modules.alias.bin"')
    alias_index = Index()
    for (i, mod) in enumerate(tlist):
        print("{0}/{1}".format(i, len(tlist)), end="\r")
        
        name = modname(mod.pathname)
        with mod.elf as file:
            for alias in file.get_strings(b".modalias"):
                alias_index.add(underscores(alias), name, mod.order)
            
            for p in file.get_strings(b".modinfo"):
                try:
                    alias = strip(p, b"alias=")
                except ValueError:
                    continue
                alias_index.add(underscores(alias), name, mod.order)
    print("{0}/{0}".format(len(tlist)))
    alias_index.write(dirname, "modules.alias.bin")
    
    print('Writing "modules.symbols.bin"')
    symbols_index = Index()
    for (name, owners) in symbol_owners.items():
        # Owners list should be ordered according to modules.order
        for owner in owners:
            symbols_index.add(b"symbol:{0}".format(name),
                modname(owner.pathname), owner.order)
    symbols_index.write(dirname, "modules.symbols.bin")

# Part of GPL 2 "depmod" port
def verify_version(version):
    (major, minor) = slice_int(version)
    if major > 2:
        return
    if major < 2:
        raise ValueError("Required at least Linux version 2")
    
    minor = strip(minor, ".")
    (sub, minor) = slice_int(minor)
    if sub > 5:
        return
    if sub < 5:
        raise ValueError("Required at least Linux version 2.5")
    
    (minor, _) = slice_int(minor)
    if minor < 48:
        raise ValueError("Required at least Linux version 2.5.48")

# Part of GPL 2 "depmod" port
def modname(path):
    name = basename(path)
    try:
        end = name.index(".")
    except ValueError:
        pass
    else:
        name = name[:end]
    return name.encode("ASCII").replace(b"-", b"_")

# Part of GPL 2 "depmod" port
class Index(object):
    NODE_PREFIX = 0x80000000
    NODE_VALUES = 0x40000000
    NODE_CHILDS = 0x20000000
    
    def __init__(self):
        self.index = defaultdict(list)
    
    def add(self, key, value, priority):
        """Order added must correspond with priority (typically modules.order
        file)"""
        self.index[key].append(Record(value=value, priority=priority))
    
    def write(self, dirname, filename):
        with open(os.path.join(dirname, filename), "wb") as file:
            file.write(struct.pack("!LHH", 0xB007F457, 2, 1))
            if not self.index:
                self.index = {b"": None}
            keys = sorted(self.index.keys())
            branches = [Record(
                prefix=0,
                end=len(keys),
                fixup=file.tell(),
            )]
            file.seek(+4, SEEK_CUR)
            
            i = 0
            while branches:
                branch = branches.pop()
                first = keys[i]
                last = keys[branch.end - 1]
                node = self.index[first]
                offset = file.tell()
                
                prefix = commonprefix(
                    (first[branch.prefix:], last[branch.prefix:]))
                prefix_len = branch.prefix + len(prefix)
                if len(first) == prefix_len:
                    i += 1
                else:
                    node = None
                
                if prefix:
                    offset |= self.NODE_PREFIX
                    file.write(prefix)
                    file.write(b"\x00")
                
                if i < branch.end:
                    offset |= self.NODE_CHILDS
                    first = keys[i][prefix_len]
                    last = last[prefix_len]
                    file.write(first)
                    file.write(last)
                    
                    ch_end = ord(last) + 1
                    span = ch_end - ord(first)
                    file.write(span * struct.pack("!L", 0))
                    fixups = file.tell()
                    
                    # Branches list is in reverse, so add to it in reverse
                    ki = branch.end
                    for ci in range(1, 1 + span):
                        ch = ch_end - ci
                        end = ki
                        while ki > i and ord(keys[ki - 1][prefix_len]) == ch:
                            ki -= 1
                        if ki >= end:
                            continue
                        
                        branches.append(Record(
                            prefix=prefix_len + 1,
                            end=end,
                            fixup = fixups - 4 * ci,
                        ))
                
                if node:
                    offset |= self.NODE_VALUES
                    file.write(struct.pack("!L", len(node)))
                    for v in node:
                        file.write(struct.pack("!L", v.priority))
                        file.write(v.value)
                        file.write(b"\x00")
                
                pos = file.tell()
                file.seek(branch.fixup)
                file.write(struct.pack("!L", offset))
                file.seek(pos)

# Part of GPL 2 "depmod" port
def underscores(string):
    res = bytearray()
    i = 0
    while i < len(string):
        c = string[i]
        
        if c == b"[":
            i = string.index(b"]", i) + 1
            continue
        if c == b"]":
            print("{0}: unexpected closing square bracket".format(
                string.decode()))
        
        if c == b"-":
            c = b"_"
        res.append(c)
        i += 1
    
    return bytes(res)

# The remaining code is not part of the GPL 2 "depmod" port

def open_elf(path):
    (payload, raw) = gzopen(path)
    with raw:
        if payload is raw:
            return elf.FileRef(path)
        else:
            return Context(elf.File(BytesIO(payload.read())))

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

def slice_int(s):
    for (i, d) in enumerate(s):
        if not d.isdigit():
            break
    else:
        i = len(s)
    return (int(s[:i]), s[i:])
