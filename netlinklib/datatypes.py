from struct import pack
from typing import Any, Tuple


class NllMsg:
    __slots__: Tuple[str]
    PACKFMT: str

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        if not args and kwargs:
            try:
                for attr in self.__slots__:
                    setattr(self, attr, kwargs[attr])
            except KeyError as e:
                raise TypeError(
                    f"Missing kwarg {e.args[0]} for {self.__class__.__name__},"
                    f" all of {self.__slots__} must be present"
                )
        elif len(args) == 1 and isinstance(args[0], bytes) and not kwargs:
            self.from_bytes(args[0])
        else:
            raise TypeError(
                f"Bad args for {self.__class__.__name__}:"
                f" args={args}, kwargs={kwargs}"
            )

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}("
            + ", ".join(
                f"{k}={repr(getattr(self, k))}" for k in self.__slots__
            )
            + ")"
        )

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, NllMsg):
            return NotImplemented
        return type(self) is type(other) and self.bytes == other.bytes

    def from_bytes(self, inp: bytes) -> None:
        ...

    @property
    def bytes(self) -> bytes:
        return pack(
            self.PACKFMT, *tuple(getattr(self, x) for x in self.__slots__)
        )