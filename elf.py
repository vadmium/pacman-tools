#! /usr/bin/env python

"""
Features:
* Python 3, also potential Python 2.6 support
* Usable with Python file objects, rather than requiring a file descriptor or
    entire file buffered in memory (as in "elffile")
* Parsing of dynamic section, including entries tagged "needed" (not in
    "pyelftools")

Reference: https://www.sco.com/developers/gabi/latest/contents.html
"""

from collections import namedtuple
from struct import Struct
from misc import SEEK_CUR
from contextlib import contextmanager
from collections import defaultdict
import builtins
from operator import itemgetter
from collections import Sequence

class Elf:
    EI_NIDENT = 16
    EI_MAG = 0
    EI_CLASS = 4
    EI_DATA = 5
    EI_OSABI = 7
    EI_ABIVERSION = 8
    
    CLASS32 = 1
    CLASS64 = 2
    
    DATA2LSB = 1
    DATA2MSB = 2
    
    def __init__(self, file):
        self.file = file
        
        ident = self.file.read(self.EI_NIDENT)
        
        if not ident[self.EI_MAG:].startswith(b"\x7FELF"):
            raise ValueError("Unexpected ELF magic number identification")
        
        for (name, index) in dict(
            elf_class=self.EI_CLASS, data=self.EI_DATA,
            osabi=self.EI_OSABI, abiversion=self.EI_ABIVERSION
        ).items():
            setattr(self, name, ord(ident[index:][:1]))
        
        self.enc = {self.DATA2LSB: "<", self.DATA2MSB: ">"}[self.data]
        format = {self.CLASS32: "L", self.CLASS64: "Q"}[self.elf_class]
        self.class_format = dict(
            I=format,
            i=format.lower(),
            X="{}x".format(Struct(self.enc + format).size)
        )
        
        (
            self.machine, self.version,
            self.phoff, self.shoff, self.flags,
            self.phentsize, self.phnum, self.shentsize, self.shnum, shstrndx,
        ) = self.read("2x HL X IIL 2x HHHHH")
        
        if shstrndx == self.SHN_UNDEF:
            self.secnames = None
        else:
            self.file.seek(self.shoff + self.shentsize * shstrndx)
            self.secnames = self.read("4x4xXX II")
    
    def matches(self, elf):
        # Ignore object file type field because it is unclear which types
        # should match
        if any(getattr(self, name) != getattr(elf, name) for name in (
            "elf_class", "data", "abiversion",
            "machine", "version", "flags",
        )):
            return False
        return not self.osabi or self.osabi == elf.osabi
    
    SHN_UNDEF = 0
    SHN_XINDEX = 0xFFFF
    
    SHT_NOBITS = 8
    
    def get_section(self, name):
        for i in range(1, self.shnum):
            self.file.seek(self.shoff + self.shentsize * i)
            (n, offset, size) = self.read("L 4xXX II")
            if self.getname(n) != name:
                continue
            return (offset, size)
        else:
            return None
    
    def getname(self, name):
        if self.secnames is None:
            return None
        else:
            return self.read_str(self.secnames, name)
    
    def get_strings(self, secname):
        sec = self.get_section(secname)
        if sec is None:
            return
        
        (start, size) = sec
        self.file.seek(start)
        while True:
            while size:
                peek = ord(self.file.read(1))
                if peek:
                    self.file.seek(-1, SEEK_CUR)
                    break
                size -= 1
            if size <= 0:
                break
            
            sym = bytearray()
            while True:
                if size <= 0:
                    raise EOFError(
                        "Unterminated string in {0}".format(secname))
                size -= 1
                
                c = ord(self.file.read(1))
                if not c:
                    break
                sym.append(c)
            
            yield bytes(sym)
    
    def read_str(self, sect, offset=None):
        """If size is not given, or offset _is_ given, then string must be
        terminated with 0. If offset is not given then string may
        additionally be terminated by the end of the section determined by
        size."""
        (start, size) = sect
        if offset is not None:
            start += offset
            if size is not None:
                size -= offset
        
        self.file.seek(start)
        str = bytearray()
        while True:
            chunk = self.STR_BUFFER
            if size is not None and size < chunk:
                chunk = size
            chunk = self.file.read(chunk)
            if not chunk:
                if offset is not None:
                    raise EOFError("Unterminated string at {0}".format(
                        start))
                else:
                    break
            if size is not None:
                size -= len(chunk)
            
            try:
                end = chunk.index(b"\x00")
            except ValueError:
                str.extend(chunk)
            else:
                str.extend(chunk[:end])
                break
        
        return bytes(str)
    STR_BUFFER = 0x100
    """Probably optimum if this covers most strings in one pass, but does not
    cause excessively long reads"""
    
    def read_segments(self):
        if not self.phoff:
            raise LookupError(
                "ELF file does not have a program header (segment) table")
        
        return Segments(self, self.phoff, self.phentsize, self.phnum)
    
    def dynamic_entries(self, sect):
        (offset, size) = sect
        entsize = self.Struct("iI").size
        if size % entsize:
            raise NotImplementedError(
                "Dynamic section size: {0}".format(size))
        
        self.file.seek(offset)
        for _ in range(size // entsize):
            yield self.read("iI")
    
    def symtab_entries(self, sect):
        (start, size) = sect
        # TODO: As tuple is to namedtuple, Struct is to -- NamedStruct!
        if self.elf_class == self.CLASS32:
            format = "L I X B 1x H"
            keys = ("name", "value", "info", "shndx")
        if self.elf_class == self.CLASS64:
            format = "L B 1x H I X"
            keys = ("name", "info", "shndx", "value")
        format = self.Struct(format)
        entsize = format.size
        
        if size % entsize:
            raise NotImplementedError(
                '".symtab" section size: {0}'.format(size))
        
        for offset in range(0, size, entsize * self.SYMTAB_BUFFER):
            self.file.seek(start + offset)
            chunk_len = min(size - offset, entsize * self.SYMTAB_BUFFER)
            chunk = self.file.read(chunk_len)
            
            for offset in range(0, chunk_len, entsize):
                values = format.unpack_from(chunk, offset)
                fields = dict(zip(keys, values))
                
                bind = fields["info"] >> 4
                type = fields["info"] & 0xF
                del fields["info"]
                
                yield self.SymtabEntry(bind=bind, type=type, **fields)
    SYMTAB_BUFFER = 0x100
    
    SymtabEntry = namedtuple("SymtabEntry", "name, value, bind, type, shndx")
    STB_WEAK = 2
    STT_LOPROC = 13
    
    def Struct(self, format):
        """Extension to struct.Struct()
        
        I (capital eye) -> unsigned word, depending on ELF class
        i (lowercase eye) -> signed word
        X (capital ex) -> padding of word size
        """
        
        for (old, new) in self.class_format.items():
            format = format.replace(old, new)
        return Struct(self.enc + format)
    
    def read(self, format):
        s = self.Struct(format)
        return s.unpack(self.file.read(s.size))
    
    EM_SPARC = 2
    EM_SPARCV9 = 43
    STT_SPARC_REGISTER = STT_LOPROC

class Segments(Sequence):
    def __init__(self, elf, phoff, phentsize, phnum):
        self.elf = elf
        
        format = {
            self.elf.CLASS32: "L II X I",
            self.elf.CLASS64: "L 4x II X I",
        }[elf.elf_class]
        
        if phentsize < self.elf.Struct(format).size:
            raise NotImplementedError("Program header entry size too small: "
                "{phentsize}".format_map(locals()))
        
        self.list = list()
        for i in range(phnum):
            self.elf.file.seek(phoff + phentsize * i)
            self.list.append(Segment(self.elf, *self.elf.read(format)))
    
    def __len__(self):
        return len(self.list)
    def __getitem__(self, i):
        return self.list[i]
    
    def read_dynamic(self):
        """Reads dynamic segments into new Dynamic() object"""
        
        dynamic = Dynamic(self.elf)
        for seg in self:
            if seg.type != seg.DYNAMIC:
                continue
            
            # Assume that the ".dynamic" _section_ is located at the start of
            # the _segment_ identified by PT_DYNAMIC, otherwise you cannot
            # find the _section_ (or the "_DYNAMIC" _symbol_ which labels it)
            # from the program (segment) header alone.
            dynamic.add((seg.offset, seg.filesz))
        
        dynamic.segments_strtab(self)
        return dynamic
    
    def map(self, start, size=None):
        """Map from memory address to file offset"""
        
        end = start
        if size is not None:
            end += size
        
        # Find a segment containing the memory region
        found = None
        for seg in self:
            if start >= seg.vaddr and end <= seg.vaddr + seg.filesz:
                # Region is contained completely within this segment
                new = start - seg.vaddr + seg.offset
                if found is not None and found != new:
                    raise ValueError("Inconsistent mapping for memory "
                        "address 0x{0:X}".format(start))
                found = new
        
        if found is None:
            raise LookupError("No segment found for 0x{0:X}".format(start))
        return found

class Segment(object):
    def __init__(self, elf, type, offset, vaddr, filesz):
        self.elf = elf
        self.type = type
        self.offset = offset
        self.vaddr = vaddr
        self.filesz = filesz
    
    DYNAMIC = 2
    INTERP = 3
    
    def read_interp(self):
        return self.elf.read_str((self.offset, self.filesz))

class Dynamic(object):
    def __init__(self, elf):
        self.elf = elf
        self.entries = defaultdict(list)
        for (name, tag) in self.tag_attrs:
            setattr(self, name, self.entries[tag])
    
    def add(self, sect):
        for (tag, value) in self.elf.dynamic_entries(sect):
            self.entries[tag].append(value)
    
    def segments_strtab(self, segments):
        strtab = self.entries[self.STRTAB]
        if strtab:
            (strtab,) = strtab
            strsz = self.entries[self.STRSZ]
            if strsz:
                (strsz,) = strsz
            else:
                strsz = None
            
            self.strtab = (segments.map(strtab, strsz), strsz)
        else:
            self.strtab = None
    
    def rel_entries(self, segments):
        for (table, size, entsize) in (
            (self.RELA, self.RELASZ, self.RELAENT),
            (self.REL, self.RELSZ, self.RELENT),
        ):
            entries = self.entries[table]
            if not entries:
                continue
            
            (table,) = entries
            (size,) = self.entries[size]
            (entsize,) = self.entries[entsize]
            table = segments.map(table, size)
            
            format = "XI"
            if entsize < self.elf.Struct(format).size:
                raise NotImplementedError("{name} entry size too small: "
                    "{entsize}".format(**locals()))
            if size % entsize:
                raise NotImplementedError(
                    "{name} table size: {size}".format(**locals()))
            
            for offset in range(table, table + size, entsize):
                self.elf.file.seek(offset)
                (info,) = self.elf.read(format)
                if self.elf.elf_class == self.elf.CLASS32:
                    sym = info >> 8
                if self.elf.elf_class == self.elf.CLASS64:
                    sym = info >> 32
                yield sym
    
    def symbol_table(self, segments):
        (symtab,) = self.entries[self.SYMTAB]
        (syment,) = self.entries[self.SYMENT]
        symtab = segments.map(symtab)
        return SymbolTable(self.elf, symtab, syment, self)
    
    NEEDED = 1
    STRTAB = 5
    SYMTAB = 6
    RELA = 7
    RELASZ = 8
    RELAENT = 9
    STRSZ = 10
    SYMENT = 11
    SONAME = 14
    RPATH = 15
    REL = 17
    RELSZ = 18
    RELENT = 19
    RUNPATH = 29
    
    tag_attrs = dict(
        rpath=RPATH, runpath=RUNPATH, soname=SONAME, needed=NEEDED,
    ).items()
    
    def read_str(self, entry):
        return self.elf.read_str(self.strtab, entry)

class SymbolTable(object):
    def __init__(self, elf, offset, entsize, dynamic):
        self.elf = elf
        self.offset = offset
        self.entsize = entsize
        self.dynamic = dynamic
        
        self.format = self.format[self.elf.elf_class]
        if self.entsize < self.elf.Struct(self.format).size:
            raise NotImplementedError("Symbol entry size too small: "
                "{self.entsize}".format(**locals()))
    
    format = {Elf.CLASS32: "L X4x B B H", Elf.CLASS64: "L B B H"}
    
    def __getitem__(self, sym):
        self.elf.file.seek(self.offset + sym * self.entsize)
        (name, info, other, shndx) = self.elf.read(self.format)
        bind = info >> 4
        type = info & 0xF
        visibility = other & 3
        if name:
            name = self.dynamic.read_str(name)
        else:
            name = None
        return dict(
            name=name, bind=bind, type=type, visibility=visibility,
            shndx=shndx,
        )
    
    LOCAL = 0
    WEAK = 2
    
    HIDDEN = 2
    INTERNAL = 1

@contextmanager
def open(filename):
    with builtins.open(filename, "rb") as f:
        yield Elf(f)

def main(elf):
    with open(elf) as elf:
        for attr in (
            "elf_class, data, osabi, abiversion, machine, version, flags"
        ).split(", "):
            print("{0}: 0x{1:X}".format(attr, getattr(elf, attr)))
        
        print("\nSegments (program headers):")
        segments = elf.read_segments()
        for seg in segments:
            print("  Type", format_tag(seg.type, seg, "INTERP, DYNAMIC"))
            if seg.type == seg.INTERP:
                print("    {0}".format(seg.read_interp()))
        
        print("\nDynamic section entries:")
        dynamic = segments.read_dynamic()
        entries = sorted(dynamic.entries.items(), key=itemgetter(0))
        for (tag, entries) in entries:
            if not entries:
                continue
            
            out = format_tag(tag, dynamic, "NEEDED, RPATH, RUNPATH, SONAME")
            print("  Tag {0} ({1})".format(out, len(entries)))
            
            str = "NEEDED, RPATH, RUNPATH, SONAME".split(", ")
            if tag in (getattr(dynamic, name) for name in str):
                for str in entries:
                    print("    {0}".format(dynamic.read_str(str)))

def format_tag(tag, obj, names):
    names = dict((getattr(obj, name), name) for name in names.split(", "))
    try:
        name = names[tag]
    except LookupError:
        name = ""
    else:
        name = " ({name})".format(**locals())
    return "0x{tag:X}{name}".format(**locals())

if __name__ == "__main__":
    from funcparams import command
    command(main)
