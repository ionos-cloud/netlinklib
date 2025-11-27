"""
Build python classes from netlink header struct definitions

Two C programs are generated at stage 1 of the process.

At stage 2, C programs are compiled and executed. One produces the final
result - Python "defs.py" with values of defines and enums, and the other
produces Python "sizes.py" to be used at stage 3.

This is stage 3. It parses headers "properly" and generates Python file
with class definition for structures.
"""

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
from typing import Any, ContextManager, IO, List, Literal, Set, Tuple, Type
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


class UnionStructVisitor(NodeVisitor):
    elems: DictT[str, OptionalT[int]]

    def __init__(self) -> None:
        self.elems = {}

    def _visit_struct_union(self, node: Node) -> None:
        super().generic_visit(node)  # proceed with children, if any
        # Struct-s and Union-s are guaranteed to have "decls", maybe None
        if numdecls := len(node.decls or []):
            print(
                "encountered",
                node.__class__.__name__,
                node.name,
                numdecls,
                "children",
            )
            for decl in node.decls:
                if isinstance(decl.type, TypeDecl):
                    if isinstance(decl.type.type, Struct):
                        print(
                            "\t",
                            decl.name,
                            "struct",
                            decl.type.type.name,
                        )
                    elif isinstance(decl.type.type, Union):
                        print(
                            "\t",
                            decl.name,
                            "union",
                            decl.type.type.name,
                        )
                    elif isinstance(decl.type.type, IdentifierType):
                        sizespec = "".join(decl.type.type.names)
                        print(
                            "\t",
                            decl.name,
                            "scalar",
                            sizespec,
                            "bitsize",
                            decl.bitsize.value if decl.bitsize else None,
                        )
                    else:
                        raise RuntimeError(
                            f"No support for {decl.name}: {decl.type.type}"
                        )
                elif isinstance(decl.type, PtrDecl):
                    if isinstance(decl.type.type.type, (Struct, Union)):
                        print(
                            "\t",
                            decl.name,
                            decl.type.type.type.name,
                            "(struct/union) pointer",
                        )
                    elif isinstance(decl.type.type.type, IdentifierType):
                        print(
                            "\t",
                            decl.name,
                            "".join(decl.type.type.type.names),
                            "(scalar) pointer",
                        )
                elif isinstance(decl.type, Union):
                    print(
                        "\t",
                        decl.name,
                        "union",
                        decl.type.name,
                    )
                elif isinstance(decl.type, Struct):
                    print(
                        "\t",
                        decl.name,
                        "struct",
                        decl.type.name,
                    )
                elif isinstance(decl.type, ArrayDecl):
                    print(
                        "\t",
                        decl.name,
                        "array",
                        decl.type.dim,
                    )
                else:
                    raise RuntimeError(
                        f"No support for {decl.name}: {decl.type}"
                    )
            self.elems[node.name] = struc_union_sizes.get(node.name, None)

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
    print("UnionStructVisitor undef elems:", list(k for k, v in structs.elems.items() if v is None))

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
