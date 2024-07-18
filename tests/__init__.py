from sys import maxsize
from logging import getLogger
from typing import Callable, Iterable, Iterator, Optional
from itertools import repeat

__all__ = ("between", "no_less_than")


def _between(low: str, what: str, high: str) -> bool:
    # `low` is inlcusive (if what == low the return is True),
    # `high` is not (if what == high the return is False)
    def __between(
        li: Iterator[int], wi: Iterator[int], hi: Iterator[int]
    ) -> bool:
        l = next(li, None)
        w = next(wi, None)
        h = next(hi, None)
        # print("l", l, "w", w, "h", h)
        if w is None:  # No need to iterate in any case
            if h is None:  # last "h" check was equal, thus "no"
                return False
            return l is None  # more digits in l means we are below it
        # Now w is not None
        if l is not None and w < l:
            return False
        if h is not None and w > h:
            return False
        # one of them equal, need to compare the next element
        return __between(
            repeat(None) if l is None or w > l else li,
            wi,
            repeat(maxsize) if h is not None and w < h else hi,
        )

    return __between(
        *((int(el) for el in arg.split(".")) for arg in (low, what, high))
    )


def between(low: str, high: str) -> Callable[[str], bool]:
    return lambda arg: _between(low, arg, high)


def less_than(high: str) -> Callable[[str], bool]:
    return lambda arg: _between("0", arg, high)


def no_less_than(low: str) -> Callable[[str], bool]:
    return lambda arg: _between(low, arg, str(maxsize))
