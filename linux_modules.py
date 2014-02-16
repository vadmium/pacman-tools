from io import BytesIO
import elf
from elftools.elf.elffile import ELFFile
from gzip import GzipFile
import os
import os.path
from io import SEEK_CUR
from collections import defaultdict
import struct
from os.path import commonprefix
from os.path import basename
import sys

MODULE_DIR = os.path.join("lib", "modules")

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
    
    verify_version(kver)
    
    dirname = os.path.join(basedir, MODULE_DIR, kver)
    if not os.access(dirname, os.W_OK):
        msg = "WARNING: {}: No write access!".format(dirname)
        print(msg, file=sys.stderr)
    
    print("Scanning modules in", dirname, file=sys.stderr)
    module_files = dict()
    tree = os.walk(dirname, onerror=raiseerror, followlinks=True)
    for (dirpath, dirnames, filenames) in tree:
        #~ print("Scanning", dirpath, file=sys.stderr)
        for f in filenames:
            if not f.endswith((".ko", ".ko.gz")):
                continue
            
            fullpath = os.path.join(dirpath, f)
            pathname = os.path.relpath(fullpath, dirname)
            if f not in module_files:
                module_files[f] = Module(open_elf(fullpath), pathname)
        
        i = 0
        while i < len(dirnames):
            if dirnames[i] in ("source", "build"):
                del dirnames[i]
            else:
                i = i + 1
    
    print('Ordering modules by "modules.order"', file=sys.stderr)
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
                
                mod["order"] = linenum
                tlist.append(mod)
    tlist.extend(module_paths.values())
    
    print("Reading symbols from modules", file=sys.stderr)
    symbol_owners = defaultdict(list)
    for (i, mod) in enumerate(tlist):
        print("{}/{}".format(i, len(tlist)), end="\r", file=sys.stderr)
        with mod.elf as file:
            for sym in elf.iter_strings(file, b"__ksymtab_strings"):
                symbol_owners[sym].append(mod)
            
            strings = file.get_section_by_name(b".strtab")
            syms = file.get_section_by_name(b".symtab")
            if strings is not None and syms is not None:
                tables = dict.fromkeys((
                    b"pci", b"usb", b"ccw", b"ieee1394", b"pnp", b"pnp_card",
                    b"input", b"serio", b"of",
                ))
                
                for sym in syms.iter_symbols():
                    prefix = b"__mod_"
                    suffix = b"_device_table"
                    if (not sym.name.startswith(prefix) or
                    not sym.name.endswith(suffix)):
                        continue
                    name = sym.name[len(prefix):-len(suffix)]
                    if name not in tables or tables[name] is not None:
                        continue
                    
                    sect = file.get_section(sym["st_shndx"])
                    if sect["sh_type"] == "SHT_NOBITS":
                        continue
                    tables[name] = sect["sh_offset"] + sym["st_value"]
    print("{0}/{0}".format(len(tlist)), file=sys.stderr)
    
    print("Reading dependencies of modules", file=sys.stderr)
    for (i, mod) in enumerate(tlist):
        print("{}/{}".format(i, len(tlist)), end="\r", file=sys.stderr)
        with mod.elf as file:
            strings = file.get_section_by_name(b".strtab")
            syms = file.get_section_by_name(b".symtab")
            if strings is None or syms is None:
                msg = '{}: no ".strtab" nor ".symtab" sections'
                print(msg.format(mod.pathname), file=sys.stderr)
                continue
            
            sparc = file["e_machine"] in {"EM_SPARC", "EM_SPARCV9"}
            for sym in syms.iter_symbols():
                if (sym["st_shndx"] != "SHN_UNDEF" or
                sparc and sym["type"] == elf.STT_SPARC_REGISTER):
                    continue
                
                if sym.name.startswith(b"."):
                    lookup = sym.name[1:]
                else:
                    lookup = sym.name
                
                try:
                    # Original "depmod" places later modules at front of hash
                    # table chain, so take latest module here
                    owner = symbol_owners[lookup][-1]
                except LookupError:
                    continue
                
                #~ msg = "{} needs {!r}: {}"
                #~ msg = msg.format(mod.pathname, name, owner.pathname)
                #~ print(msg, file=sys.stderr)
                mod.deps.add(owner)
    print("{0}/{0}".format(len(tlist)), file=sys.stderr)
    
    deps_index = Index()
    print('Generating "modules.dep"', file=sys.stderr)
    with open(os.path.join(dirname, "modules.dep"), "w") as file:
        for (i, mod) in enumerate(tlist):
            dfs_steps = list()
            ancestors = set()
            visited = set()
            postorder = list()
            
            node = mod
            while True:
                dfs_steps.append(dict(
                    node=node, queue=iter(node.deps)))
                ancestors.add(node)
                
                while dfs_steps:
                    current = dfs_steps[-1]
                    try:
                        node = next(current["queue"])
                    except StopIteration:
                        node = current["node"]
                        ancestors.remove(node)
                        visited.add(node)
                        postorder.append(node)
                        dfs_steps.pop()
                    else:
                        if node in ancestors:
                            msg = ("{}: Ignoring cyclic dependency of {} "
                                "on {}")
                            msg = msg.format(mod.pathname,
                                current["node"].pathname, node.pathname)
                            print(msg, file=sys.stderr)
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
    
    print('Writing "modules.dep.bin"', file=sys.stderr)
    deps_index.write(dirname, "modules.dep.bin")
    
    print('Generating "modules.alias.bin"', file=sys.stderr)
    alias_index = Index()
    for (i, mod) in enumerate(tlist):
        print("{}/{}".format(i, len(tlist)), end="\r", file=sys.stderr)
        
        name = modname(mod.pathname)
        with mod.elf as file:
            for alias in elf.iter_strings(file, b".modalias"):
                alias_index.add(underscores(alias), name, mod.order)
            
            for p in elf.iter_strings(file, b".modinfo"):
                prefix = b"alias="
                if not p.startswith(prefix):
                    continue
                alias = p[len(prefix):]
                alias_index.add(underscores(alias), name, mod.order)
    print("{0}/{0}".format(len(tlist)), file=sys.stderr)
    alias_index.write(dirname, "modules.alias.bin")
    
    print('Writing "modules.symbols.bin"', file=sys.stderr)
    symbols_index = Index()
    for (name, owners) in symbol_owners.items():
        # Owners list should be ordered according to modules.order
        for owner in owners:
            symbols_index.add(b"symbol:" + name,
                modname(owner.pathname), owner.order)
    symbols_index.write(dirname, "modules.symbols.bin")

# Part of GPL 2 "depmod" port
class Module:
    def __init__(self, elf, pathname):
        self.elf = elf
        self.pathname = pathname
        self.order = self.INDEX_PRIORITY_MIN
        self.deps = set()
    
    INDEX_PRIORITY_MIN = ~(~0 << 32)

# Part of GPL 2 "depmod" port
def verify_version(version):
    (major, minor) = slice_int(version)
    if major > 2:
        return
    if major < 2:
        raise ValueError("Required at least Linux version 2")
    
    if not minor.startswith("."):
        raise ValueError('Linux version 2 missing ".minor" part')
    (sub, minor) = slice_int(minor[1:])
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
        self.index[key].append(dict(value=value, priority=priority))
    
    def write(self, dirname, filename):
        with open(os.path.join(dirname, filename), "wb") as file:
            file.write(struct.pack("!LHH", 0xB007F457, 2, 1))
            if not self.index:
                self.index = {b"": None}
            keys = sorted(self.index.keys())
            branches = [dict(
                prefix=0,
                end=len(keys),
                fixup=file.tell(),
            )]
            file.seek(+4, SEEK_CUR)
            
            i = 0
            while branches:
                branch = branches.pop()
                first = keys[i]
                last = keys[branch["end"] - 1]
                node = self.index[first]
                offset = file.tell()
                
                prefix = commonprefix(
                    (first[branch["prefix"]:], last[branch["prefix"]:]))
                prefix_len = branch["prefix"] + len(prefix)
                if len(first) == prefix_len:
                    i += 1
                else:
                    node = None
                
                if prefix:
                    offset |= self.NODE_PREFIX
                    file.write(prefix)
                    file.write(b"\x00")
                
                if i < branch["end"]:
                    offset |= self.NODE_CHILDS
                    first = keys[i][prefix_len:prefix_len + 1]
                    last = last[prefix_len:prefix_len + 1]
                    file.write(first)
                    file.write(last)
                    
                    ch_end = ord(last) + 1
                    span = ch_end - ord(first)
                    file.write(span * struct.pack("!L", 0))
                    fixups = file.tell()
                    
                    # Branches list is in reverse, so add to it in reverse
                    ki = branch["end"]
                    for ci in range(1, 1 + span):
                        ch = ch_end - ci
                        end = ki
                        while ki > i and keys[ki - 1][prefix_len] == ch:
                            ki -= 1
                        if ki >= end:
                            continue
                        
                        branches.append(dict(
                            prefix=prefix_len + 1,
                            end=end,
                            fixup = fixups - 4 * ci,
                        ))
                
                if node:
                    offset |= self.NODE_VALUES
                    file.write(struct.pack("!L", len(node)))
                    for v in node:
                        file.write(struct.pack("!L", v["priority"]))
                        file.write(v["value"])
                        file.write(b"\x00")
                
                pos = file.tell()
                file.seek(branch["fixup"])
                file.write(struct.pack("!L", offset))
                file.seek(pos)

# Part of GPL 2 "depmod" port
def underscores(string):
    res = bytearray()
    i = 0
    while i < len(string):
        c = string[i:i + 1]
        
        if c == b"[":
            i = string.index(b"]", i) + 1
            continue
        if c == b"]":
            msg = "{}: unexpected closing square bracket"
            print(msg.format(string.decode()), file=sys.stderr)
        
        if c == b"-":
            c = b"_"
        res.extend(c)
        i += 1
    
    return bytes(res)

# The remaining code is not part of the GPL 2 "depmod" port

def open_elf(path):
    (payload, raw) = gzopen(path)
    with raw:
        if payload is raw:  # Uncompressed file
            return FilenameElf(path)
        else:
            return DataElf(payload.read())

class FilenameElf:
    def __init__(self, filename):
        self._filename = filename
    
    def __enter__(self):
        try:
            self._f = open(self._filename, "rb")
            return ELFFile(self._f)
        except:
            self._f.close()
            raise
    
    def __exit__(self, *exc):
        self._f.close()

class DataElf:
    def __init__(self, data):
        self._file = BytesIO(data)
    
    def __enter__(self):
        return ELFFile(self._file)
    
    def __exit__(self, *exc):
        pass

def gzopen(path):
    raw = open(path, "rb")
    try:
        header = raw.read(2)
        raw.seek(0)
        if header == bytearray((31, 139)):
            return (GzipFile(fileobj=raw), raw)
        else:
            return (raw, raw)
    except:
        raw.close()
        raise

def slice_int(s):
    for (i, d) in enumerate(s):
        if not d.isdigit():
            break
    else:
        i = len(s)
    return (int(s[:i]), s[i:])

def raiseerror(err):
    raise err
