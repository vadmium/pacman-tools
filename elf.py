#! /usr/bin/env python3

"""
Features:
* Python 3 support
* Usable with Python file objects, rather than requiring a file descriptor or
    entire file buffered in memory (as in "elffile")
* Parsing of dynamic section, including entries tagged "needed" (not in
    "pyelftools")

Reference: https://www.sco.com/developers/gabi/latest/contents.html
"""

from collections import namedtuple
from elftools.construct import (Struct, Union)
from io import SEEK_CUR
from collections import defaultdict
from collections import (Sequence, Mapping)
from shorthand import bitmask
from elftools.common.utils import (struct_parse, parse_cstring_from_stream)
from elftools.elf.sections import Symbol
from elftools.elf.relocation import Relocation

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
    
    ET_EXEC = 2
    
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
            self.type, self.machine, self.version,
            self.phoff, self.shoff, self.flags,
            self.phentsize, self.phnum, self.shentsize, self.shnum, shstrndx,
        ) = self.read("HHL X IIL 2x HHHHH")
        
        if shstrndx == self.SHN_UNDEF:
            self.secnames = None
        else:
            self.file.seek(self.shoff + self.shentsize * shstrndx)
            self.secnames = self.read("4x4xXX II")

def matches(elf, header):
    # Ignore object file type field because it is unclear which types
    # should match
    
    ident_a = elf.header['e_ident']
    ident_b = header['e_ident']
    if any(ident_a[name] != ident_b[name] for name in (
        'EI_CLASS', 'EI_DATA', 'EI_ABIVERSION',
    )):
        return False
    
    if any(elf.header[name] != header[name] for name in (
        'e_machine', 'e_version', 'e_flags',
    )):
        return False
    
    abi_a = ident_a['EI_OSABI']
    abi_b = ident_b['EI_OSABI']
    
    # Treating Linux aka GNU ABI as System V aka "none". Most ELF files have
    # "none", but require "libc" which has GNU, but "libc" has "ld-linux-x86-
    # 64.so.2" listed as "needed", which has the "none" ABI again.
    if abi_a == 'ELFOSABI_LINUX':
        abi_a = 'ELFOSABI_SYSV'
    if abi_b == 'ELFOSABI_LINUX':
        abi_b = 'ELFOSABI_SYSV'
    
    return abi_a == abi_b
    
    SHN_UNDEF = 0
    SHN_XINDEX = 0xFFFF
    
    SHT_NOBITS = 8
    
    def getname(self, name):
        if self.secnames is None:
            return None
        else:
            return self.read_str(self.secnames, name)

def iter_strings(elf, secname):
    sec = elf.get_section_by_name(secname)
    if sec is None:
        return
    
    elf.stream.seek(sec["sh_offset"])
    size = sec["sh_size"]
    while True:
        while size:
            peek = ord(elf.stream.read(1))
            if peek:
                elf.stream.seek(-1, SEEK_CUR)
                break
            size -= 1
        if size <= 0:
            break
        
        sym = bytearray()
        while True:
            if size <= 0:
                msg = "Unterminated string in {!r}".format(secname)
                raise EOFError(msg)
            size -= 1
            
            c = ord(elf.stream.read(1))
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
                    raise EOFError("Unterminated string at {}".format(start))
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
            msg = '".symtab" section size: {}'.format(size)
            raise NotImplementedError(msg)
        
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

STT_SPARC_REGISTER = "STT_LOPROC"

class Segments(Sequence):
    def __init__(self, elf):
        self.elf = elf
        self.list = tuple(self.elf.iter_segments())
    
    def __len__(self):
        return len(self.list)
    def __getitem__(self, i):
        return self.list[i]
    
    def read_dynamic(self):
        """Reads dynamic segments into new Dynamic() object"""
        
        dynamic = Dynamic(self, self.elf)
        for seg in self:
            if seg['p_type'] != 'PT_DYNAMIC':
                continue
            
            # Assume that the ".dynamic" _section_ is located at the start of
            # the _segment_ identified by PT_DYNAMIC, otherwise you cannot
            # find the _section_ (or the "_DYNAMIC" _symbol_ which labels it)
            # from the program (segment) header alone.
            self.elf.stream.seek(seg['p_offset'])
            dynamic.add(self.elf.stream, seg['p_filesz'])
        
        dynamic.strtab = dynamic.get_stringtable()
        return dynamic
    
    def map(self, start, size=None):
        """Map from memory address to file offset"""
        
        end = start
        if size is not None:
            end += size
        
        # Find a segment containing the memory region
        found = None
        for seg in self:
            if (start >= seg['p_vaddr'] and
            end <= seg['p_vaddr'] + seg['p_filesz']):
                # Region is contained completely within this segment
                new = start - seg['p_vaddr'] + seg['p_offset']
                if found is not None and found != new:
                    msg = "Inconsistent mapping for memory address 0x{:X}"
                    raise ValueError(msg.format(start))
                found = new
        
        if found is None:
            raise LookupError("No segment found for 0x{:X}".format(start))
        return found

class Dynamic(object):
    def __init__(self, segments, elf):
        self.segments = segments
        self.elf = elf
        
        self.Elf_Dyn = Struct('Elf_Dyn',
            elf.structs.Elf_sxword('d_tag'),
            #~ Union('d_un',
            elf.structs.Elf_xword('d_un'),
                #~ elf.structs.Elf_addr('d_ptr'),
            #~ ),
        )
        
        self.entries = defaultdict(list)
        for (name, tag) in self.tag_attrs:
            setattr(self, name, self.entries[tag])
    
    def add(self, stream, size):
        entsize = self.Elf_Dyn.sizeof()
        if size % entsize:
            msg = 'Dynamic section size: {}'.format(size)
            raise NotImplementedError(msg)
        
        for _ in range(size // entsize):
            entry = struct_parse(self.Elf_Dyn, stream)
            self.entries[entry['d_tag']].append(entry['d_un'])
    
    def get_stringtable(self):
        """Returns the StringTable object for the dynamic linking array"""
        
        strtab = self.entries[self.STRTAB]
        if not strtab:
            raise LookupError(
                "String table entry not found in dynamic linking array")
        
        (strtab,) = strtab
        strsz = self.entries[self.STRSZ]
        if strsz:
            (strsz,) = strsz
            #~ strsz = strsz['d_val']
        else:
            strsz = None
        
        strtab = self.segments.map(strtab,strsz)#['d_ptr'], strsz)
        return StringTable(self.elf.stream, strtab, strsz)
    
    def rel_entries(self):
        for (type, size) in (
            (self.RELA, self.RELASZ),
            (self.REL, self.RELSZ),
        ):
            entries = self.entries[type]
            if entries:
                yield from self.rel_table_entries(entries, size, type)
        
        entries = self.entries[self.JMPREL]
        if entries:
            (pltrel,) = self.entries[self.PLTREL]
            #~ pltrel = pltrel['d_val']
            yield from self.rel_table_entries(entries, self.PLTRELSZ, pltrel)
    
    def rel_table_entries(self, entries, size, type):
        (entsize, Struct) = {
            self.RELA: (self.RELAENT, self.elf.structs.Elf_Rela),
            self.REL: (self.RELENT, self.elf.structs.Elf_Rel),
        }[type]
        
        (table,) = entries
        (size,) = self.entries[size]
        #~ size = size['d_val']
        (entsize,) = self.entries[entsize]
        #~ entsize = entsize['d_val']
        table = self.segments.map(table,size)#['d_ptr'], size)
        
        if entsize < Struct.sizeof():
            msg = "{} entry size too small: {}"
            raise NotImplementedError(msg.format(Struct.name, entsize))
        if size % entsize:
            msg = "{} table size: {}"
            raise NotImplementedError(msg.format(Struct.name, size))
        
        # TODO: mmap
        # TODO: read rel table in one go
        for offset in range(table, table + size, entsize):
            self.elf.stream.seek(offset)
            entry = struct_parse(Struct, self.elf.stream)
            yield Relocation(entry, self.elf)
    
    def symbol_table(self):
        (symtab,) = self.entries[self.SYMTAB]
        (syment,) = self.entries[self.SYMENT]
        symtab = self.segments.map(symtab)#['d_ptr'])
        return SymbolTable(self.elf.stream, symtab, syment,#['d_val'],
            self.elf, self.strtab)
    
    def symbol_hash(self, symtab):
        for (tag, Class) in ((self.GNU_HASH, GnuHash), (self.HASH, Hash)):
            hash = self.entries[tag]
            if not hash:
                continue
            (hash,) = hash
            hash = self.segments.map(hash)#['d_ptr'])
            return Class(self.elf, hash, symtab)
        return dict()
    
    NEEDED = 1
    PLTRELSZ = 2
    HASH = 4
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
    PLTREL = 20
    JMPREL = 23
    RUNPATH = 29
    
    GNU_HASH = 0x6FFFFEF5
    
    tag_attrs = dict(
        rpath=RPATH, runpath=RUNPATH, soname=SONAME, needed=NEEDED,
    ).items()

class SymbolTable(object):
    def __init__(self, stream, offset, entsize, elf, stringtable):
        self.stream = stream
        self.offset = offset
        self.entsize = entsize
        self.stringtable = stringtable
        
        self.Elf_Sym = elf.structs.Elf_Sym
        if self.entsize < self.Elf_Sym.sizeof():
            msg = "Symbol entry size too small: {}"
            raise NotImplementedError(msg.format(self.entsize))
    
    def __getitem__(self, sym):
        """Get Symbol() object for given table index"""
        
        self.stream.seek(self.offset + sym * self.entsize)
        entry = struct_parse(self.Elf_Sym, self.stream)
        
        name = entry['st_name']
        if name:
            name = self.stringtable[name]
        else:
            name = None
        
        return Symbol(entry, name)

# Does not really implement a proper mapping because __iter__() yields values
# rather than keys, but some of the mixin methods might be handy
class BaseHash(Mapping):
    def __init__(self, elf, offset, symtab):
        self.stream = elf.stream
        self.symtab = symtab
        self.stream.seek(offset)

class Hash(BaseHash):
    def __init__(self, elf, *pos, **kw):
        BaseHash.__init__(self, elf, *pos, **kw)
        self.Elf_word = elf.structs.Elf_word
        self.header = Struct('Hash table header',
            self.Elf_word('nbucket'), self.Elf_word('nchain'))
        self.header = struct_parse(self.header, self.stream)
        self.buckets = self.stream.tell()
        self.chain = self.buckets + self.header['nbucket'] * 4
    
    def __len__(self):
        return self.header['nchain'] - 1
    
    def __iter__(self):
        end = self.chain + self.header['nchain'] * 4
        for offset in range(self.buckets, end, 4):
            self.stream.seek(offset)
            sym = struct_parse(self.Elf_word(None), self.stream)
            if sym:
                yield self.symtab[sym]
    
    def __getitem__(self, name):
        hash = 0
        for c in name:
            hash = (hash << 4) + c
            hash = (hash ^ hash >> 24 & 0xF0) & bitmask(28)
        
        self.stream.seek(self.buckets + hash % self.header['nbucket'] * 4)
        while True:
            index = struct_parse(self.Elf_word(None), self.stream)
            if not index:
                raise KeyError(name)
            
            sym = self.symtab[index]
            if sym.name == name:
                return sym
            
            self.stream.seek(self.chain + index * 4)

# Mostly based on https://blogs.oracle.com/ali/entry/gnu_hash_elf_sections
class GnuHash(BaseHash):
    def __init__(self, elf, *pos, **kw):
        BaseHash.__init__(self, elf, *pos, **kw)
        self.Elf_word = elf.structs.Elf_word
        self.Maskword = elf.structs.Elf_xword("Maskword")
        self.header = Struct('GNU hash table header',
            self.Elf_word('nbuckets'),
            self.Elf_word('symndx'),
            self.Elf_word('maskwords'),
            self.Elf_word('shift2'),
        )
        self.header = struct_parse(self.header, self.stream)
        self.filter = self.stream.tell()
        self.maskword_size = self.Maskword.sizeof()
        self.maskword_bits = self.maskword_size * 8
        self.buckets = (self.filter +
            self.header['maskwords'] * self.maskword_size)
        self.values = self.buckets + self.header['nbuckets'] * 4
    
    def __len__(self):
        raise NotImplementedError()
    
    def __iter__(self):
        for offset in range(self.buckets, self.values, 4):
            self.stream.seek(offset)
            bucket = struct_parse(self.Elf_word(None), self.stream)
            if not bucket:
                continue
            sym = self.symtab[bucket]
            while True:
                offset = self.values + (bucket - self.header['symndx']) * 4
                value = struct_parse(self.Elf_word(None), self.stream,
                    stream_pos=offset)
                yield self.symtab[bucket]
                if value & 1:
                    break
                bucket += 1
    
    def __getitem__(self, name):
        hash = 5381
        for c in name:
            hash = hash * 33 + c & bitmask(32)
        
        word = hash // self.maskword_bits % self.header['maskwords']
        self.stream.seek(self.filter + word * self.maskword_size)
        word = struct_parse(self.Maskword, self.stream)
        mask = 1 << hash % self.maskword_bits
        mask |= 1 << (hash >> self.header['shift2']) % self.maskword_bits
        if ~word & mask:
            raise KeyError(name)
        
        self.stream.seek(self.buckets + hash % self.header['nbuckets'] * 4)
        bucket = struct_parse(self.Elf_word(None), self.stream)
        if not bucket:
            raise KeyError(name)
        
        while True:
            offset = self.values + (bucket - self.header['symndx']) * 4
            value = struct_parse(self.Elf_word(None), self.stream,
                stream_pos=offset)
            if value & ~1 == hash & ~1:
                sym = self.symtab[bucket]
                if sym.name == name:
                    return sym
            
            if value & 1:
                raise KeyError(name)
            bucket += 1

class StringTable(object):
    def __init__(self, stream, offset, size):
        self.stream = stream
        self.offset = offset
        self.size = size
    def __getitem__(self, offset):
        return parse_cstring_from_stream(self.stream, self.offset + offset)

def main(elf, relocs=False, dyn_syms=False, lookup=()):
    from elftools.elf.elffile import ELFFile
    
    with open(elf, "rb") as elf:
        elf = ELFFile(elf)
        
        print("Header:")
        for attr in ("EI_CLASS", "EI_DATA", "EI_OSABI", "EI_ABIVERSION"):
            print("  {}: {}".format(attr, elf["e_ident"][attr]))
        for attr in ("e_type", "e_machine", "e_version", "e_flags"):
            print("  {}: {}".format(attr, elf[attr]))
        
        dump_segments(elf, relocs=relocs, dyn_syms=dyn_syms, lookup=lookup)

def dump_segments(elf, *, relocs, dyn_syms, lookup):
    from os import fsencode
    
    segments = Segments(elf)
    if not segments:
        print("\nNo segments (program headers)")
        if relocs:
            print("Not showing relocation entries "
                "without dynamic linking segment")
        if dyn_syms:
            print("Not showing symbols without dynamic linking segment")
        if lookup:
            print("Not looking up symbols without dynamic linking segment")
        return
    
    print("\nSegments (program headers):")
    for seg in segments:
        if seg["p_type"] == "PT_INTERP":
            print("  PT_INTERP:", repr(seg.get_interp_name()))
        else:
            print("  {}".format(seg["p_type"]))
    
    print("\nDynamic section entries:")
    dynamic = segments.read_dynamic()
    entries = sorted(dynamic.entries.items())
    for (tag, entries) in entries:
        if not entries:
            continue
        
        out = format_tag(tag, dynamic,
            "NEEDED, RPATH, RUNPATH, SONAME, "
            "REL, RELA, HASH, GNU_HASH"
        )
        print("  Tag {} ({})".format(out, len(entries)))
        
        str = "NEEDED, RPATH, RUNPATH, SONAME".split(", ")
        if tag in (getattr(dynamic, name) for name in str):
            for str in entries:
                print("    {!r}".format(dynamic.strtab[str]))#["d_val"]]))
    
    if relocs:
        print("\nRelocation entries:")
        symtab = dynamic.symbol_table()
        found = False
        for rel in dynamic.rel_entries():
            found = True
            if rel["r_info_sym"]:
                sym = symtab[rel["r_info_sym"]]
                print("  {}".format(format_symbol(sym)))
            else:
                print("  Sym UNDEF")
        if not found:
            print("  (None)")
    
    if dyn_syms:
        print("\nSymbols from hash table:")
        symtab = dynamic.symbol_table()
        hash = dynamic.symbol_hash(symtab)
        for sym in hash:
            print("  {}".format(format_symbol(sym)))
    
    if lookup:
        print("\nSymbol lookup results:")
    for name in lookup:
        symtab = dynamic.symbol_table()
        hash = dynamic.symbol_hash(symtab)
        try:
            sym = hash[fsencode(name)]
        except LookupError:
            print("  Symbol not found:", name)
        else:
            print("  {}".format(format_symbol(sym)))

def format_tag(tag, obj, names):
    names = dict((getattr(obj, name), name) for name in names.split(", "))
    try:
        name = names[tag]
    except LookupError:
        name = ""
    else:
        name = " ({})".format(name)
    return "0x{:X}{}".format(tag, name)

def format_symbol(sym):
    return "{!r}: {}, {}, {}, shndx {}".format(
        sym.name,
        sym.entry["st_info"]["bind"],
        sym.entry["st_info"]["type"],
        sym.entry["st_other"]["visibility"],
        sym.entry["st_shndx"],
    )

if __name__ == "__main__":
    from funcparams import command
    command(main)
