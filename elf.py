# Reference: https://www.sco.com/developers/gabi/latest/contents.html

from collections import namedtuple
from struct import Struct
from lib import SEEK_CUR

class File:
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
        
        self.class_type = {self.CLASS32: "L", self.CLASS64: "Q"}[
            self.elf_class]
        self.enc = {self.DATA2LSB: "<", self.DATA2MSB: ">"}[self.data]
        self.class_size = Struct(self.enc + self.class_type).size
        
        self.file.seek(+2, SEEK_CUR)
        (self.machine, self.version) = self.read("HL")
        self.file.seek(+self.class_size, SEEK_CUR)
        (self.phoff, self.shoff, self.flags) = self.read(
            self.class_type + self.class_type + "L")
        self.file.seek(+2, SEEK_CUR)
        (self.phentsize, self.phnum, self.shentsize, self.shnum,
            shstrndx) = self.read("HHHHH")
        
        if shstrndx == self.SHN_UNDEF:
            self.secnames = None
        else:
            self.file.seek(self.shoff + self.shentsize * shstrndx +
                4 + 4 + self.class_size + self.class_size)
            self.secnames = self.read(self.class_type + self.class_type)
    
    def matches(self, elf):
        # Ignore object file type field because it is unclear which types
        # should match
        return all(getattr(self, name) == getattr(elf, name) for name in (
            "elf_class", "data", "osabi", "abiversion",
            "machine", "version", "flags",
        ))
    
    SHN_UNDEF = 0
    SHN_XINDEX = 0xFFFF
    
    SHT_NOBITS = 8
    
    def get_section(self, name):
        for i in range(1, self.shnum):
            self.file.seek(self.shoff + self.shentsize * i)
            (n,) = self.read("H")
            if self.getname(n) != name:
                continue
            
            self.file.seek(self.shoff + self.shentsize * i +
                4 + 4 + self.class_size + self.class_size)
            return self.read(self.class_type + self.class_type)
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
            
            found = None
            for seg in self.ph_entries():
                if strtab >= seg.vaddr and end <= seg.vaddr + seg.filesz:
                    new = strtab - seg.vaddr + seg.offset
                    if found is not None and found != new:
                        raise ValueError(
                            "Inconsistent mapping: 0x{:X}".format(strtab))
                    found = new
            
            if found is None:
                raise LookupError(
                    "No segment found for 0x{:X}".format(strtab))
            
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
    
    def read_str(self, (start, size), offset=None):
        """If size is not given, or offset _is_ given, then string must be
        terminated with 0. If offset is not given then string may
        additionally be terminated by the end of the section determined by
        size."""
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
        ph_offset_offset = {self.CLASS32: 0, self.CLASS64: 4}[self.elf_class]
        
        for i in range(self.phnum):
            self.file.seek(self.phoff + self.phentsize * i)
            (type,) = self.read("L")
            self.file.seek(+ph_offset_offset, SEEK_CUR)
            (offset, vaddr) = self.read(self.class_type + self.class_type)
            self.file.seek(+self.class_size, SEEK_CUR)
            (filesz,) = self.read(self.class_type)
            yield self.PhEntry(type=type, offset=offset, vaddr=vaddr,
                filesz=filesz)
    
    PhEntry = namedtuple("PhEntry", "type, offset, vaddr, filesz")
    
    def pt_dynamic_entries(self, seg):
        # Assume that the ".dynamic" _section_ is located at the start of the
        # _segment_ identified by PT_DYNAMIC, otherwise you cannot find the
        # _section_ (or the _DYNAMIC _symbol_ which labels it) from the
        # program (segment) header alone.
        
        entsize = self.class_size + self.class_size
        if seg.filesz % entsize:
            raise NotImplementedError(
                "Segment PT_DYNAMIC file size: {0}".format(seg.filesz))
        
        for i in range(seg.offset, seg.offset + seg.filesz, entsize):
            self.file.seek(i)
            (tag,) = self.read(self.class_type.lower())
            yield tag
    
    def symtab_entries(self, (start, size)):
        # TODO: As tuple is to namedtuple, Struct is to -- NamedStruct!
        if self.elf_class == self.CLASS32:
            format = "L L 4x B 1x H"
            keys = ("name", "value", "info", "shndx")
        if self.elf_class == self.CLASS64:
            format = "L B 1x H Q"
            keys = ("name", "info", "shndx", "value")
        format = Struct(self.enc + format)
        entsize = 4 + 1 + 1 + 2 + self.class_size + self.class_size
        
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
    
    def read(self, format):
        s = Struct(self.enc + format)
        return s.unpack(self.file.read(s.size))
    
    EM_SPARC = 2
    EM_SPARCV9 = 43
    STT_SPARC_REGISTER = STT_LOPROC

class FileRef:
    def __init__(self, filename):
        self.filename = filename
    
    def __enter__(self):
        self.f = None
        try:
            self.f = open(self.filename, "rb")
            return File(self.f)
        except BaseException:
            if self.f is not None:
                self.f.close()
            raise
    
    def __exit__(self, *exc):
        self.f.close()
