"""
Build python classes from netlink header struct definitions

Two C programs are generated at stage 1 of the process.

At stage 2, C programs are compiled and executed. One produces the final
result - Python "defs.py" with values of defines and enums, and the other
produces Python "sizes.py" to be used at stage 3.

This is stage 3. It parses headers "properly" and generates Python file
with class definition for structures.
"""

from enum import Enum
from io import TextIOWrapper
from os import getenv
from pycparser import CParser
from pycparser.c_ast import (
    ArrayDecl,
    Decl,
    IdentifierType,
    Node,
    NodeVisitor,
    PtrDecl,
    Struct,
    TypeDecl,
    Union,
)
from struct import calcsize
from subprocess import PIPE, Popen, run, STDOUT
from sys import argv
from tempfile import mkstemp
from typing import (
    Any,
    ContextManager,
    Dict,
    IO,
    List,
    Literal,
    NamedTuple,
    Set,
    Tuple,
    Type,
)
from typing import Dict as DictT
from typing import Literal as LiteralT
from typing import Optional as OptionalT
from types import TracebackType
from black import format_file_contents, Mode

from headers import INC, HEADERS, PREINC
from sizes import struc_union_sizes

CPP = "/usr/bin/cpp"

TDICT = {
    "__kernel_sa_family_t": ("H", 0),
    "__be16": ("B", 2),
    "__be32": ("B", 4),
    "__be64": ("B", 8),
    "__u8": ("B", 0),
    "__s8": ("b", 0),
    "char": ("b", 0),
    "signedchar": ("B", 0),
    "unsignedchar": ("B", 0),
    "__u16": ("H", 0),
    "short": ("h", 0),
    "signedshort": ("h", 0),
    "unsignedshort": ("H", 0),
    "__s32": ("l", 0),
    "long": ("l", 0),
    "signedlong": ("l", 0),
    "unsignedlong": ("L", 0),
    "__s64": ("q", 0),
    "int": ("i", 0),
    "signed": ("I", 0),
    "unsigned": ("I", 0),
    "signedint": ("I", 0),
    "unsignedint": ("I", 0),
    "unsignedlong": ("L", 0),
    "__u32": ("L", 0),
    "__u64": ("Q", 0),
    "__time_t": ("Q", 0),  # TODO make this work for 32bit time_t when needed
    "__atomic_wide_counter": ("Q", 0),  # TODO it's a typedef from struct
    "__suseconds_t": ("q", 0),  # TODO make this work for 32bit
    "__syscall_slong_t": ("q", 0),  # TODO make this work for 32bit
    "__pthread_list_t": ("B", 16),  # TODO it's a typedef from struct
    "__atomic_wide_counter": ("Q", 0),
    "sa_family_t": ("H", 0),
}


def _mkfmt(tspc, dim, sizecache=None):
    if tspc.startswith("struct"):
        assert sizecache is not None, "No parse nested struct w/o size cache"
        name = tspc[6:]
        if name not in sizecache:
            raise RuntimeError(f"Could not find the size of struct {name}")
        return "s", 0 if dim == 0 else sizecache[name]
    fmt, rev = TDICT[tspc]
    if fmt == "B" and dim:  # More than one byte: parse into as many `bytes`
        return "s", dim
    if rev:  # Non-native byte order: parse into specified number of `bytes`
        if dim:
            raise NotImplementedError(
                "No support for arrays with elements of non-native byte order"
            )
        return "s", rev
    return fmt, dim


def _slotname(nm):
    # Attributes that start with "__" are "class-private", have to avoid.
    # Attribute named "from" is not possible, mangle it to start with "_".
    if nm.startswith("__"):
        return nm[1:]
    if nm in ("from", "bytes"):
        return "_" + nm
    return nm


class Kind(Enum):
    Struct = 1
    Union = 2
    Pointer = 3
    Scalar = 4


class Element(NamedTuple):
    """Attribute of the generated object"""

    name: str
    kind: Kind  # of the element of the array, if this is an array
    size: int  # of the element of the array, if this is an array
    dim: OptionalT[int] = None  # None: "not an array", 0 - size undefined


class Item(NamedTuple):
    """Description of the NllHdr object to generate"""

    name: str
    kind: Kind  # only Struct or Union. Do we need Union?...
    size: int
    elements: Tuple[Element, ...]


class UnionStructVisitor(NodeVisitor):

    def _visit_struct_union(self, node: Node) -> None:
        super().generic_visit(node)  # proceed with children, if any

        ikind = Kind.Struct if isinstance(node, Struct) else Kind.Union
        isize = struc_union_sizes.get(node.name, None)
        # Struct-s and Union-s are guaranteed to have "decls", maybe None
        numdecls = len(node.decls or [])
        if numdecls < 1:
            # This is a reference to a struct/union declared elsewhere
            return

        elems: List[Element] = []
        for decl in node.decls:
            # Collect Elements for this Item
            dim: OptionalT[int] = None
            if isinstance(decl.type, ArrayDecl):
                dim = struc_union_sizes.get(f"{node.name}.{decl.name}", None)
                if isinstance(decl.type.type.type, IdentifierType):
                    ekind = Kind.Scalar
                    esize = struc_union_sizes.get(
                        " ".join(
                            nm
                            for nm in decl.type.type.type.names
                            if nm != "unsigned"
                        )
                    )
                elif isinstance(decl.type.type.type, (Struct, Union)):
                    ekind = (
                        Kind.Struct
                        if isinstance(decl.type.type.type, Struct)
                        else Kind.Union
                    )
                    esize = struc_union_sizes.get(
                        decl.type.type.type.name, None
                    )
                elif isinstance(decl.type.type, PtrDecl):
                    ekind = Kind.Pointer
                    esize = struc_union_sizes.get("__pointer", None)
                else:
                    raise RuntimeError(decl.type.type.type)
            elif isinstance(decl.type, TypeDecl):
                if isinstance(decl.type.type, IdentifierType):
                    ekind = Kind.Scalar
                    esize = struc_union_sizes.get(
                        " ".join(
                            nm
                            for nm in decl.type.type.names
                            if nm != "unsigned"
                        )
                    )
                elif isinstance(decl.type.type, (Struct, Union)):
                    ekind = (
                        Kind.Struct
                        if isinstance(decl.type.type, Struct)
                        else Kind.Union
                    )
                    esize = struc_union_sizes.get(
                        decl.type.type.name, None
                    )
                else:
                    raise RuntimeError(decl.type.type.type)
            elif isinstance(decl.type, PtrDecl):
                ekind = Kind.Pointer
                esize = struc_union_sizes.get("__pointer", None)
            elif isinstance(decl.type, (Struct, Union)):
                ekind = (
                    Kind.Struct
                    if isinstance(decl.type, Struct)
                    else Kind.Union
                )
                esize = struc_union_sizes.get(
                    decl.type.name, None
                )
            elems.append(Element(decl.name, ekind, esize, dim))

        # node.name and size are attributes for the Item instance
        item = Item(node.name, ikind, isize, tuple(elems))
        print(item)  # Generate python code from it here

    visit_Union = _visit_struct_union
    visit_Struct = _visit_struct_union


if __name__ == "__main__":
    extra_headers = tuple(
        []
        if (envval := getenv("NLL_EXTRA_HEADERS")) is None
        else envval.split(",")
    )

    with Popen(
        [CPP, "-Ifake_libc_include"],
        stdin=PIPE,
        stdout=PIPE,
        stderr=PIPE,
        encoding="ascii",
    ) as proc:
        assert isinstance(proc.stdout, TextIOWrapper) and isinstance(
            proc.stderr, TextIOWrapper
        )
        proc.stdin.write(
            PREINC
            + "\n".join(
                f"#include <{hdr}>" for hdr in (HEADERS + extra_headers)
            )
        )
        proc.stdin.close()
        ast = CParser().parse(proc.stdout.read(), "combined_headers.c")
    structs = UnionStructVisitor()
    structs.visit(ast)

    exit(0)

    quote = '"""'
    classfile = f"""\
{quote}Autogenerated file, do not edit!{quote}

# pylint: disable-all
from struct import pack
from typing import Any, Callable, ClassVar, Dict, List, TypeVar, Union

Accum = TypeVar("Accum")
class NllHdr(Dict[str, Any]):
    PACKFMT: ClassVar[str]
    SIZE: ClassVar[int]

    def __bytes__(self) -> bytes:
        return pack(
            self.PACKFMT,
            *(
                default if callable(kwarg) else kwarg
                for kwarg, default in zip(
                    self.values(),
                    self.__init__.__kwdefaults__.values(),  # type: ignore
                )
            ),
        )
"""
    structsize: DictT[str, int] = {  # TODO kill this hack
        "in6_addr": 16,
        "iphdr": 20,
        "ethtool_rx_ntuple_flow_spec": 176,
    }
    for clname, _elems in structs.items():
        elems = tuple(
            (
                _slotname(nm),
                *_mkfmt(tspc, eval(dim) if dim else "", sizecache=structsize),
            )
            for nm, tspc, dim in _elems
        )
        classfile += f"\n\nclass {clname}(NllHdr):\n"
        classfile += f'\t"""struct {clname}"""\n'
        packfmt = "=" + "".join(
            f"{dim}{fmt}" for _, fmt, dim in elems if dim != 0
        )
        size = calcsize(packfmt)
        structsize[clname] = size
        classfile += f'\tPACKFMT = "{packfmt}"\n'
        classfile += f"\tSIZE = {size}\n\n"
        init_args = ", ".join(
            "{name}: Union[Callable[[Accum, {t}], Accum], {t}] = {d}".format(
                name=name,
                **(
                    {"t": "bytes", "d": str(b"\0" * dim)}
                    if fmtchar == "s" and dim != ""
                    else (
                        {"t": "List[int]", "d": str([0] * dim)}
                        if dim
                        else {"t": "int", "d": "0"}
                    )
                ),
            )
            for name, fmtchar, dim in elems
        )
        super_args = ", ".join(f"{name}={name}" for name, *_ in elems)
        classfile += f"\tdef __init__(self, *, {init_args}) -> None:\n"
        classfile += f"\t\tsuper().__init__({super_args})\n"
    with open(argv[1], "w") as cl_out:
        print(
            format_file_contents(
                classfile, fast=False, mode=Mode(line_length=79)
            ),
            file=cl_out,
            end="",
        )
