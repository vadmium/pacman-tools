#! /usr/bin/env python3

"""
Features:
* Python 3 support
* Usable with Python file objects, rather than requiring a file descriptor or
    entire file buffered in memory (as in "elffile")

Reference: https://www.sco.com/developers/gabi/latest/contents.html
"""

from collections import namedtuple
from elftools.construct import (Struct, Union)
from io import SEEK_CUR
from collections import defaultdict
from collections import (Sequence, Mapping)
from elftools.common.utils import (struct_parse, parse_cstring_from_stream)
from elftools.elf.sections import Symbol
from elftools.elf.relocation import Relocation
from elftools.elf.descriptions import describe_dyn_tag

class Elf:
    EI_NIDENT = 16
    EI_MAG = 0
    EI_CLASS = 4
    EI_DATA = 5
    EI_OSABI = 7
    EI_ABIVERSION = 8
    
    ET_EXEC = 2

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

def iter_strings(elf, secname):
    sec = elf.get_section_by_name(secname)
    if sec is None:
        return
    
    elf.stream.seek(sec["sh_offset"])
    size = sec["sh_size"]
    while True:
        while size:
            peek = elf.stream.read(1)
            if peek != b"\x00":
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
            
            c = elf.stream.read(1)
            if c == b"\x00":
                break
            sym.extend(c)
        
        yield bytes(sym)
    
    STB_WEAK = 2

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
            
            dynamic.add(seg)
        
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
        
        self.entries = defaultdict(list)
        for (name, tag) in self.tag_attrs:
            setattr(self, name, self.entries[tag])
    
    def add(self, dyn):
        for tag in dyn.iter_tags():
            self.entries[tag.entry.d_tag].append(tag.entry.d_val)
    
    def get_stringtable(self):
        """Returns the StringTable object for the dynamic linking array"""
        
        strtab = self.entries["DT_STRTAB"]
        if not strtab:
            raise LookupError("No string table in dynamic linking array")
        
        (strtab,) = strtab
        strsz = self.entries["DT_STRSZ"]
        if strsz:
            (strsz,) = strsz
        else:
            strsz = None
        
        strtab = self.segments.map(strtab, strsz)
        return StringTable(self.elf.stream, strtab, strsz)
    
    def rel_entries(self):
        for (type, size) in (
            ("DT_RELA", "DT_RELASZ"),
            ("DT_REL", "DT_RELSZ"),
        ):
            entries = self.entries[type]
            if entries:
                yield from self.rel_table_entries(entries, size, type)
        
        entries = self.entries["DT_JMPREL"]
        if entries:
            (pltrel,) = self.entries["DT_PLTREL"]
            pltrel = describe_dyn_tag(pltrel)
            yield from self.rel_table_entries(entries, "DT_PLTRELSZ", pltrel)
    
    def rel_table_entries(self, entries, size, type):
        (entsize, Struct) = {
            "DT_RELA": ("DT_RELAENT", self.elf.structs.Elf_Rela),
            "DT_REL": ("DT_RELENT", self.elf.structs.Elf_Rel),
        }[type]
        
        (table,) = entries
        (size,) = self.entries[size]
        (entsize,) = self.entries[entsize]
        table = self.segments.map(table, size)
        
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
        (symtab,) = self.entries["DT_SYMTAB"]
        (syment,) = self.entries["DT_SYMENT"]
        symtab = self.segments.map(symtab)
        return SymbolTable(self.elf.stream, symtab, syment,
            self.elf, self.strtab)
    
    def symbol_hash(self, symtab):
        for (tag, Class) in (("DT_GNU_HASH", GnuHash), ("DT_HASH", Hash)):
            hash = self.entries[tag]
            if not hash:
                continue
            (hash,) = hash
            hash = self.segments.map(hash)
            return Class(self.elf, hash, symtab)
        return dict()
    
    tag_attrs = (
        ("rpath", "DT_RPATH"), ("runpath", "DT_RUNPATH"),
        ("soname", "DT_SONAME"), ("needed", "DT_NEEDED"),
    )

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
    '''Dump information from an ELF file'''
    from elftools.elf.elffile import ELFFile
    
    with open(elf, "rb") as elf:
        elf = ELFFile(elf)
        
        print("Header:")
        for attr in ("EI_CLASS", "EI_DATA", "EI_OSABI", "EI_ABIVERSION"):
            print("  {}: {}".format(attr, elf["e_ident"][attr]))
        for attr in ("e_type", "e_machine", "e_version", "e_flags"):
            print("  {}: {}".format(attr, elf[attr]))
        
        dump_segments(elf, relocs=relocs, dyn_syms=dyn_syms, lookup=lookup)
        
        print("\nSections:")
        for sect in elf.iter_sections():
            print("  {!r}: {}".format(sect.name, sect["sh_type"]))

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
    
    print("\nDynamic linking entries:")
    dynamic = segments.read_dynamic()
    entries = sorted(dynamic.entries.items())
    for (tag, entries) in entries:
        if not entries:
            continue
        
        print("  Tag {} ({})".format(tag, len(entries)))
        
        strs = {"DT_NEEDED", "DT_RPATH", "DT_RUNPATH", "DT_SONAME"}
        if tag in strs:
            for str in entries:
                print("    {!r}".format(dynamic.strtab[str]))
    
    if relocs:
        print("\nRelocation entries:")
        symtab = dynamic.symbol_table()
        count = 0
        for rel in dynamic.rel_entries():
            count += 1
            if rel["r_info_sym"]:
                sym = symtab[rel["r_info_sym"]]
                print("  {}".format(format_symbol(sym)))
            else:
                print("  Sym UNDEF")
        print("Total entries: {}".format(count))
    
    if dyn_syms:
        symtab = dynamic.symbol_table()
        hash = dynamic.symbol_hash(symtab)
        print("\nSymbols from hash table ({}):".format(type(hash).__name__))
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

def bitmask(bits):
    return ~(~0 << bits)

if __name__ == "__main__":
    from clifunc import run
    run(main)
