""" Common datatypes for netlinklib moduels, including autogenerated code """

from struct import pack, unpack
from typing import Any, Callable, ClassVar, Dict, get_type_hints, List, Tuple

from .defs import *  # pylint: disable=wildcard-import, unused-wildcard-import

__all__ = (
    "RtaDesc",
    "NllException",
    "NllError",
    "NllDumpInterrupted",
    "NllMsg",
    "nlmsgerr",
    "tc_prio_qopt",
)

RtaDesc = Dict[int, Tuple[Callable[..., Any], Any]]


class NllException(BaseException):
    """Any exception originating from here"""


class NllError(NllException):
    """Error originating from here"""


class NllDumpInterrupted(NllException):
    """ "Dump interrupted" condition reported by the kernel"""


class NllMsg:
    """Encoder / decoder for a `struct` used in netlink messages"""

    __slots__: ClassVar[Tuple[str]]
    PACKFMT: ClassVar[str]
    SIZE: ClassVar[int]

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        try:  # Faster than checking for len(args), and this is a bottleneck
            self.from_bytes(args[0][: self.SIZE])
            self.remainder = args[0][self.SIZE :]
            return
        except IndexError:
            pass
        hints = get_type_hints(self)
        for attr in self.__slots__:
            if attr == "remainder":
                continue
            try:
                setattr(self, attr, kwargs[attr])
            except KeyError as e:
                if hints[attr] is int:
                    setattr(self, attr, 0)
                else:
                    raise TypeError(
                        f"Missing non-integer kwarg {e.args[0]}"
                        f" of type {hints[attr]}"
                        f" for {self.__class__.__name__},"
                    ) from e

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}("
            + ", ".join(
                f"{k}={repr(getattr(self, k))}"
                for k in self.__slots__
                if k != "remainder"
            )
            + ")"
        )

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, NllMsg):
            return NotImplemented
        return type(self) is type(other) and self.bytes == other.bytes

    def from_bytes(
        self, inp: bytes
    ) -> None:  # pylint: disable=unused-argument
        """Parser for binary messages"""

    @property
    def bytes(self) -> bytes:
        """Represent message as bytes"""
        return pack(
            self.PACKFMT,
            *tuple(
                getattr(self, x) for x in self.__slots__ if x != "remainder"
            ),
        )


# The class for struct nlmsgerr is defined by hand below. It cannot be
# autogenerated with a reasonable effort, because the struct in the
# kernel header file is defined as a _container_, with another struct
# inside. All(?) other structs are defined as _headers_ of a message,
# and consist of only scalar values, making it easy to autogenerate
# Python classes for them.
class nlmsgerr(NllMsg):
    """The _header_ of struct nlmsgerr (not the whole struct)"""

    __slots__ = ("error",)
    PACKFMT = "=i"
    SIZE = 4
    remainder: bytes
    error: int  #  i

    def from_bytes(self, inp: bytes) -> None:
        (self.error,) = unpack(self.PACKFMT, inp)


class tc_prio_qopt(NllMsg):
    """TODO cover structs with arrays by automatic processing"""

    __slots__ = ("bands", "priomap")
    PACKFMT = f"=i{TC_PRIO_MAX+1}B"
    SIZE = 4 + TC_PRIO_MAX + 1
    bands: int  # i
    priomap: List[int]  # {TC_PRIO_MAX+1}B

    def from_bytes(self, inp: bytes) -> None:
        (self.bands, *self.priomap) = unpack(self.PACKFMT, inp)
