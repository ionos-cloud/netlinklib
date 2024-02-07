"""
Build python definitions from netlink header definitions

Include build dependency on `linux-libc-dev` package

Example from https://stackoverflow.com/questions/58732872/can-python-load-definitions-from-a-c-header-file


To verify result against manually assembled defs file:
    for k, v in vars(odefs).items():
        if vars(defs).get(k) != v:
            print(k, v, vars(defs).get(k))

"""

from contextlib import ExitStack
from os import unlink
from os.path import join
from struct import calcsize
from sys import argv, stdout
from tempfile import mkstemp
from typing import ContextManager, IO, List, Literal, Tuple, Type
from typing import Literal as LiteralT
from typing import Optional as OptionalT
from types import TracebackType
from black import format_file_contents, Mode
from pyparsing import *
from re import match

INC = "/usr/include"

HEADERS = (
    "linux/if_link.h",
    "linux/netlink.h",
    "linux/genetlink.h",
    "linux/rtnetlink.h",
    "linux/neighbour.h",
)

# tcm_block_index is the only #define that aliases the element of a struct
EXCLUDE = "(^__)|(^tcm_block_index$)"

CCODE = (
    """#include <stdio.h>

struct vn {char *n; int v;} list[] = {""",
    """\t{NULL, 0},
};

int main(int const argc, char const * const argv[])
{
\tstruct vn *cur;

\tprintf("\\"\\"\\" Autogenerated file, do not edit! \\"\\"\\"\\n\\n");
\tfor (cur = list; cur->n != NULL; cur++) {
\t\tprintf("%s = %d\\n", cur->n, cur->v);
\t}
\treturn 0;
}""",
)


class mkstemp_n:
    def __init__(self, count: int = 2) -> None:
        self.temps = tuple(mkstemp() for _ in range(count))

    def __enter__(self) -> Tuple[IO, ...]:
        files: List[IO] = []
        with ExitStack() as stk:
            for fd, _ in self.temps:
                files.append(
                    stk.enter_context(open(fd, "r+", encoding="ascii"))
                )
                self.undo = stk.pop_all()
        return tuple(files)

    def __exit__(
        self,
        ecls: OptionalT[Type[BaseException]],
        eobj: OptionalT[BaseException],
        etrc: OptionalT[TracebackType],
    ) -> LiteralT[False]:
        with self.undo:
            pass
        for _, fn in self.temps:
            try:
                unlink(fn)
            except OSError:
                pass
        return False


# syntax we don't want to see in the final parse tree
# LPAREN, RPAREN, LBRACE, RBRACE, EQ, COMMA = Suppress.using_each("(){}=,")
identifier = pyparsing_common.identifier
integer = pyparsing_common.integer
c_style_comment = Combine(Regex(r"/\*(?:[^*]|\*(?!/))*") + "*/")
CHAR, SHORT, INT, LONG = (Literal(x) for x in ("char", "short", "int", "long"))
stdtype = CHAR ^ SHORT ^ INT ^ LONG
LPAREN, RPAREN, LBRACE, RBRACE, LBRACKET, RBRACKET, EQ, COMMA, SEMICOLON = (
    Suppress(x) for x in "(){}[]=,;"
)
arith_op = Word("+-*/", max=1)
arith_elem = identifier ^ integer
arith_expr = Group(arith_elem + (arith_op + arith_elem)[...])
paren_expr = arith_expr ^ (LPAREN + arith_expr + RPAREN)
enumValue = Group(identifier("name") + Optional(EQ + paren_expr("value")))
enumList = Group(enumValue + (COMMA + enumValue)[...] + Optional(COMMA))
enum = (
    Suppress("enum")
    + Optional(identifier("ename"))
    + LBRACE
    + enumList("names")
    + RBRACE
)
enum.ignore(c_style_comment)

typespec = Combine(
    Group(Optional(Literal("unsigned")) + stdtype) ^ identifier,
    adjacent=False,
)
struct_elem = Group(
    typespec("typespec")
    + identifier("name")
    + Optional(LBRACKET + integer("dim") + RBRACKET)
    + SEMICOLON
)
struct_elist = Group(struct_elem[...])
struct = (
    Suppress("struct")
    + identifier("name")
    + LBRACE
    + struct_elist("elist")
    + RBRACE
)
struct.ignore(c_style_comment)

define = LineStart() + Suppress("#define") + identifier("name") + White()
define.ignore(c_style_comment)

TDICT = {
    "__kernel_sa_family_t": ("H", 0),
    "__be16": ("H", 2),
    "__u8": ("B", 0),
    "char": ("b", 0),
    "unsignedchar": ("B", 0),
    "__u16": ("H", 0),
    "short": ("h", 0),
    "unsignedshort": ("H", 0),
    "__s32": ("l", 0),
    "int": ("i", 0),
    "unsigned": ("I", 0),
    "unsignedint": ("I", 0),
    "__u32": ("L", 0),
    "__u64": ("Q", 0),
}


def _mkfmt(tspc, dim):
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
    if nm == "from":
        return "_" + nm
    return nm


if __name__ == "__main__":
    names = set()
    structs = {}
    for infn in HEADERS:
        with mkstemp_n() as (defs, rest), open(join(INC, infn)) as inp:
            line = ""
            for rline in inp.readlines():
                line += rline
                if line.endswith("\\\n"):
                    line = line.rstrip("\\\n")
                    continue
                if line.startswith("#define"):
                    defs.write(line)
                else:
                    rest.write(line)
                line = ""
            defs.seek(0)
            rest.seek(0)
            # find instances of defines ignoring other syntax
            for item, start, stop in define.scanString(defs.read()):
                if item.name:
                    if match(EXCLUDE, item.name):
                        continue
                    names.add(item.name)
                else:
                    print("****************\n", item.dump())
            # find instances of enums ignoring other syntax
            for item, start, stop in enum.scanString(rest.read()):
                for entry in item.names:
                    if not entry.name.startswith("__"):
                        names.add(entry.name)
            rest.seek(0)
            for item, start, stop in struct.scanString(rest.read()):
                structs[item.name] = (
                    (elem.name, elem.typespec, elem.dim) for elem in item.elist
                )

    with open("mkdefs.c", "w") as out:
        for hdr in HEADERS:
            print(f"#include <{hdr}>", file=out)
        print(CCODE[0], file=out)
        for name in names:
            print(f'\t{{ "{name}", {name} }},', file=out)
        print(CCODE[1], file=out)

    classfile = '""" Autogenerated file, do not edit! """\n\n'
    classfile += "# pylint: disable=too-many-lines\n\n"
    classfile += "from struct import unpack\n"
    classfile += "from typing import List\n"
    classfile += "from .datatypes import NllMsg, nlmsgerr"
    for clname, _elems in structs.items():
        elems = tuple(
            (_slotname(nm), *_mkfmt(tspc, dim)) for nm, tspc, dim in _elems
        )
        classfile += f"\n\nclass {clname}(NllMsg):\n"
        classfile += f'\t"""struct {clname}"""\n'
        classfile += (
            '\t__slots__ = ("remainder", '
            + ", ".join(f'"{nm}"' for nm, *_ in elems)
            + ")\n"
        )
        packfmt = "=" + "".join(f"{dim}{fmt}" for _, fmt, dim in elems)
        lside = " ".join(
            f"{'*' if fmt != 's' and dim else ''}self.{nm},"
            for nm, fmt, dim in elems
        )
        classfile += f'\tPACKFMT = "{packfmt}"\n'
        classfile += f"\tSIZE = {calcsize(packfmt)}\n"
        classfile += "\tremainder: bytes\n"
        for name, fmtchar, dim in elems:
            typ = (
                "bytes"
                if fmtchar == "s" and dim
                else "List[int]"
                if dim
                else "int"
            )
            classfile += f"\t{name}: {typ}  # {dim} {fmtchar}\n"
        classfile += "\tdef from_bytes(self, inp: bytes) -> None:\n"
        classfile += f"\t\t{lside} = unpack(self.PACKFMT, inp)\n"
    with open(argv[1], "w") if len(argv) > 1 else stdout as cl_out:
        print(
            format_file_contents(
                classfile, fast=False, mode=Mode(line_length=79)
            ),
            file=cl_out,
            end="",
        )
