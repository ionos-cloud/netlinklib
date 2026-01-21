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
    Constant,
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
from struct import error as StructError
from subprocess import PIPE, Popen, run, STDOUT
from sys import argv, stderr
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

FMTDICT: Dict[Tuple[str, ...], str] = {
    ("atomic_bool",): "B",  # Artefact of fake_includes
    ("unsigned", "short", "int"): "H",
    ("unsigned", "int"): "I",
    ("__u8",): "B",
    ("__be64",): "8B",
    ("__s8",): "b",
    ("__s64",): "q",
    ("__u32",): "L",
    ("unsigned", "short"): "H",
    ("int",): "i",
    ("__kernel_sa_family_t",): "H",
    ("__s32",): "l",
    ("__sum16",): "H",
    ("unsigned",): "I",
    ("short",): "h",
    ("__u64",): "Q",
    ("unsigned", "char"): "B",
    ("__be32",): "4B",
    ("__be16",): "2B",
    ("__u16",): "H",
    ("signed", "char"): "b",
    ("unsigned", "long"): "L",
    ("char",): "b",
}


size_cache: Dict[str, int] = {}


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
    fmt: str  # for Scalar, value from FMTDICT
    dim: OptionalT[int] = None  # None: "not an array", 0 - size undefined

    def aname(self) -> str:
        # Attributes that start with "__" are "class-private", have to avoid.
        # Attribute named "from" is not possible, mangle it to start with "_".
        if self.name.startswith("__"):
            return self.name[1:]
        if self.name in ("from", "bytes"):
            return "_" + self.name
        return self.name

    def fmtspec(self, _parentname: str) -> str:
        if self.kind is Kind.Struct or self.kind is Kind.Union:
            return str(self.size) + "s"
        if self.kind is Kind.Pointer:
            return "Q"
        if self.kind is Kind.Scalar:
            return self.fmt



class Item(NamedTuple):
    """Description of the NllHdr object to generate"""

    name: str
    kind: Kind  # only Struct or Union. Do we need Union?...
    size: int
    bitsize: OptionalT[int]
    elements: Tuple[Element, ...]

    def asclass(self) -> str:
        if self.name is None or self.size is None:
            return ""

        classfile = f"\n\nclass {self.name}(NllHdr):\n"
        classfile += f'\t"""{self.kind.name} {self.name}"""\n'
        packfmt = "=" + "".join(el.fmtspec(self.name) for el in self.elements)
        try:
            size = calcsize(packfmt)
        except StructError as e:
            print(e, packfmt, self.name, file=stderr)
            return ""
        size_cache[self.name] = size
        classfile += f'\tPACKFMT = "{packfmt}"\n'
        classfile += f"\tSIZE = {size}\n\n"
        classfile += f"\tSPARSE_SIZE = {self.size}\n\n"
        init_args = ", ".join(
            "{name}: Union[Callable[[Accum, {t}], Accum], {t}] = {d}".format(
                name=el.aname(),
                **(
                    {"t": "bytes", "d": str(b"\0" * el.dim)}
                    if el.fmt == "s" and el.dim != ""
                    else (
                        {"t": "List[int]", "d": str([0] * el.dim)}
                        if el.dim
                        else {"t": "int", "d": "0"}
                    )
                ),
            )
            for el in self.elements
            if el.name is not None
        )
        super_args = ", ".join(
            f"{el.aname()}={el.aname()}"
            for el in self.elements
            if el.name is not None
        )
        classfile += f"\tdef __init__(self, *, {init_args}) -> None:\n"
        classfile += f"\t\tsuper().__init__({super_args})\n"
        return classfile


class UnionStructVisitor(NodeVisitor):
    outstring: str  # String with python code, new content appended to it

    def __init__(self, outstring: str) -> None:
        super().__init__()
        self.outstring = outstring

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
            fmt: Tuple[int, str] = (0, "")
            bitsize: Optional[int] = None
            if isinstance(decl.type, ArrayDecl):
                dim: OptionalT[int] = struc_union_sizes.get(
                    f"{node.name}.{decl.name}", None
                )
                membertype = decl.type.type
            else:
                dim: OptionalT[int] = None
                membertype = decl.type

            if isinstance(membertype, TypeDecl):
                innertype = membertype.type
            elif isinstance(membertype, (Struct, Union, PtrDecl)):
                innertype = membertype
            else:
                raise RuntimeError(f"Unfamiliar {membertype} in {node.name}")

            if decl.bitsize is not None and not isinstance(
                innertype, IdentifierType
            ):
                raise RuntimeError(
                    f"bitsize is present for non-identifier: {decl}"
                )

            if isinstance(innertype, IdentifierType):
                ekind = Kind.Scalar
                esize = struc_union_sizes.get(
                    " ".join(nm for nm in innertype.names if nm != "unsigned")
                )
                fmt = FMTDICT[tuple(sorted(innertype.names, reverse=True))]
                if decl.bitsize is not None:
                    if (
                        not isinstance(decl.bitsize, Constant)
                        or decl.bitsize.type != "int"
                    ):
                        raise RuntimeError(f"Unsupported bitsize in {decl}")
                    bitsize = decl.bitsize.value
            elif isinstance(innertype, Struct):
                ekind = Kind.Struct
                esize = struc_union_sizes.get(innertype.name, None)
            elif isinstance(innertype, Union):
                ekind = Kind.Union
                esize = struc_union_sizes.get(innertype.name, None)
            elif isinstance(innertype, PtrDecl):
                ekind = Kind.Pointer
                esize = struc_union_sizes.get("__pointer", None)
            else:
                raise RuntimeError(f"Unfamiliar {decl} in {node.name}")

            elems.append(Element(decl.name, ekind, esize, fmt, dim))

        self.outstring += Item(
            node.name, ikind, isize, bitsize, tuple(elems)
        ).asclass()

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

    classhdr = f"""\
\"\"\" Autogenerated file, do not edit! \"\"\"

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
    structs = UnionStructVisitor(classhdr)
    structs.visit(ast)
    if False:
        print(
            format_file_contents(
                structs.outstring, fast=False, mode=Mode(line_length=79)
            ),
            end="",
        )
    else:
        print(structs.outstring)
