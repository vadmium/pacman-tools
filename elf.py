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
from lib import SEEK_CUR
from contextlib import contextmanager

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
    
    PT_DYNAMIC = 2
    PT_INTERP = 3
    
    DT_NEEDED = 1
    DT_STRTAB = 5
    DT_STRSZ = 10
    DT_SONAME = 14
    DT_RPATH = 15
    DT_RUNPATH = 29
    
    dynamic_lists = dict(
        rpath=DT_RPATH, runpath=DT_RUNPATH, soname=DT_SONAME,
    )
    Dynamic = namedtuple("Dynamic",
        ("strtab",) + tuple(dynamic_lists.keys()))
    
    def read_dynamic(self):
        """Reads entire dynamic segment or section and returns object holding
        commonly used entries from it"""
        
        entries = dict((dt, []) for dt in self.dynamic_lists.values())
        entries.update(dict.fromkeys((self.DT_STRTAB, self.DT_STRSZ)))
        for seg in self.ph_entries():
            if seg.type != self.PT_DYNAMIC:
                continue
            
            for tag in self.pt_dynamic_entries(seg):
                try:
                    list = entries[tag]
                except LookupError:
                    continue
                
                (value,) = self.read(self.class_type)
                if list is None:
                    entries[tag] = value
                else:
                    list.append(value)
        
        strtab = entries[self.DT_STRTAB]
        if strtab is not None:
            end = strtab
            strsz = entries[self.DT_STRSZ]
            if strsz is not None:
                end += strsz
            
            # Find a segment containing strtab, to convert from memory offset
            # to file offset
            found = None
            for seg in self.ph_entries():
                if strtab >= seg.vaddr and end <= seg.vaddr + seg.filesz:
                    # strtab is contained completely within this segment
                    new = strtab - seg.vaddr + seg.offset
                    if found is not None and found != new:
                        raise ValueError(
                            "Inconsistent mapping: 0x{0:X}".format(strtab))
                    found = new
            
            if found is None:
                raise LookupError(
                    "No segment found for 0x{0:X}".format(strtab))
            
            strtab = (found, strsz)
        
        return self.Dynamic(strtab=strtab, **dict((name, entries[dt])
            for (name, dt) in self.dynamic_lists.items()))
    
    def read_dyn_list(self, get_dynamic, name):
        dynamic = get_dynamic()
        return list(self.read_str(dynamic.strtab, offset)
            for offset in getattr(dynamic, name))
    
    def read_dyn_str(self, get_dynamic, name):
        dynamic = get_dynamic()
        return self.read_str(dynamic.strtab, getattr(dynamic, name))
    
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
    
    def ph_entries(self):
        format = {
            self.CLASS32: "L II X I",
            self.CLASS64: "L 4x II X I",
        }[self.elf_class]
        
        for i in range(self.phnum):
            self.file.seek(self.phoff + self.phentsize * i)
            (
                type,
                offset, vaddr,
                filesz,
            ) = self.read(format)
            yield self.PhEntry(type=type, offset=offset, vaddr=vaddr,
                filesz=filesz)
    
    PhEntry = namedtuple("PhEntry", "type, offset, vaddr, filesz")
    
    def pt_dynamic_entries(self, seg):
        # Assume that the ".dynamic" _section_ is located at the start of the
        # _segment_ identified by PT_DYNAMIC, otherwise you cannot find the
        # _section_ (or the _DYNAMIC _symbol_ which labels it) from the
        # program (segment) header alone.
        
        entsize = self.Struct("iX").size
        if seg.filesz % entsize:
            raise NotImplementedError(
                "Segment PT_DYNAMIC file size: {0}".format(seg.filesz))
        
        self.file.seek(seg.offset)
        for _ in range(seg.filesz // entsize):
            (tag,) = self.read("iX")
            yield tag
    
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

@contextmanager
def open(filename):
    with open(self.filename, "rb") as f:
        yield Elf(f)
