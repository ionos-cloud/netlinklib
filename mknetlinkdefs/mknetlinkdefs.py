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
from sys import stdout
from tempfile import mkstemp
from typing import ContextManager, IO, List, Literal, Tuple, Type
from typing import Literal as LiteralT
from typing import Optional as OptionalT
from types import TracebackType
from pyparsing import *
from pyparsing import common
from re import match

SRC = [
    "/usr/include/linux/if_link.h",
    "/usr/include/linux/netlink.h",
    "/usr/include/linux/genetlink.h",
    "/usr/include/linux/rtnetlink.h",
]

# tcm_block_index is the only #define that aliases the element of a struct
EXCLUDE = "(^__)|(^tcm_block_index$)"


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
LPAREN, RPAREN, LBRACE, RBRACE, EQ, COMMA = Suppress.using_each("(){}=,")
_enum = Suppress("enum")
arith_op = one_of("+ - * /")
arith_elem = common.identifier ^ common.integer
arith_expr = Group(arith_elem + (arith_op + arith_elem)[...])
paren_expr = arith_expr ^ (LPAREN + arith_expr + RPAREN)
enumValue = Group(
    common.identifier("name") + Optional(EQ + paren_expr("value"))
)
enumList = Group(enumValue + (COMMA + enumValue)[...] + Optional(COMMA))
enum = (
    _enum
    + Optional(common.identifier("ename"))
    + LBRACE
    + enumList("names")
    + RBRACE
)
enum.ignore(c_style_comment)

define = LineStart() + Suppress("#define") + common.identifier("name") + White()
define.ignore(c_style_comment)


if __name__ == "__main__":
    with open("p.h", "w") as out:
        for infn in SRC:
            with mkstemp_n() as (defs, rest), open(infn) as inp:
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
                for item, start, stop in define.scan_string(defs.read()):
                    if item.name:
                        if match(EXCLUDE, item.name):
                            continue
                        print(
                            f'\t{{ "{item.name}", {item.name} }},'
                            f" /* define */",
                            file=out,
                        )
                    else:
                        print("****************\n", item.dump())
                # find instances of enums ignoring other syntax
                for item, start, stop in enum.scan_string(rest.read()):
                    idx = 0
                    for entry in item.names:
                        do_print = True
                        if entry.value != "":
                            try:
                                idx = int(entry.value)
                            except TypeError:
                                do_print = False
                        if do_print and not entry.name.startswith("__"):
                            print(
                                f'\t{{ "{entry.name}", {entry.name} }},'
                                f" /* enum {item.ename} */",
                                file=out,
                            )
                        idx += 1
