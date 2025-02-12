""" Netlink dump implementation core functions """

from abc import abstractmethod
from collections import ChainMap
from functools import partial, reduce
from os import getpid, strerror
from socket import AF_NETLINK, NETLINK_ROUTE, SOCK_NONBLOCK, SOCK_RAW, socket
from struct import error as StructError, pack, unpack
from sys import byteorder
from typing import (
    Any,
    Callable,
    Dict,
    Generic,
    Iterable,
    Iterator,
    List,
    Literal,
    Optional,
    Sequence,
    Tuple,
    TypeVar,
    Union,
    cast,
)
from ipaddress import IPv4Address, IPv6Address, ip_address

from .defs import *  # pylint: disable=wildcard-import, unused-wildcard-import
from .classes import NllHdr, nlmsgerr, nlmsghdr, rtattr

__all__ = (
    "NlaIp4",
    "NlaIp6",
    "NlaMac",
    "NlaStr",
    "NlaInt8",
    "NlaUInt8",
    "NlaInt16",
    "NlaBe16",
    "NlaUInt16",
    "NlaUBe16",
    "NlaInt32",
    "NlaBe32",
    "NlaUInt32",
    "NlaUBe32",
    "NlaInt64",
    "NlaBe64",
    "NlaUInt64",
    "NlaUBe64",
    "NlaUnion",
    "NllAttr",
    "NllDumpInterrupted",
    "NllError",
    "NllException",
    "NllMsg",
    "StopParsing",
    "nll_get_dump",
    "nll_listen",
    "nll_make_event_listener",
    "nll_transact",
)
SOL_NETLINK = 270

Accum = TypeVar("Accum")
T = TypeVar("T")


class NllException(Exception):
    """Any exception originating from here"""


class NllError(NllException):
    """Error originating from here"""


class NllDumpInterrupted(NllException):
    """ "Dump interrupted" condition reported by the kernel"""


class StopParsing(Exception):
    pass


class NllMsg:
    """
    Fundimental unit of netlink operation. Consists of header (struct)
    and payload (sequence of nested NllMsgs). If "size" attribute is
    provided, data is only partially consumed during parsing. If "tag"
    attribute is provided, parsing of payload is done in a dispatched
    manner, selecting correct parser using the field indicated by "tag".
    """

    tag: Optional[int] = None

    def __init__(
        self,
        hdr: NllHdr,
        *args: "NllMsg",
        size_field: Optional[str] = None,
        tag_field: Optional[str] = None,
    ) -> None:
        self.hdr = hdr
        self.args = args
        # Use struct field names to determine the indexes of
        # the values retrieved during unpack() operation
        # and save for use in parsing.
        indexes = dict(map(reversed, enumerate(hdr)))  # type: ignore
        self.size_idx = indexes.get(size_field)
        self.tag_idx = indexes.get(tag_field)
        self.hdr_callbacks = tuple(
            kwarg if callable(kwarg) else None for field, kwarg in hdr.items()
        )
        self.dispatcher: Optional[_Dispatcher] = (
            _Dispatcher(*args) if args else None
        )

    def __bytes__(self) -> bytes:
        return bytes(self.hdr) + self.encode_payload()

    def encode_payload(self) -> bytes:
        return b"".join(bytes(arg) for arg in self.args)

    def parse(self, accum: Accum, data: bytes) -> Tuple[Accum, bytes]:
        """
        Given accumulator object and unparsed bytestring, consume
        1) header section using callbacks to fill accumulator or
        abort using StopParsing and 2) payload section, if one exists.
        Returns updated accumulator and whatever remains of the blob.
        """

        hdr_vals = unpack(self.hdr.PACKFMT, data[: self.hdr.SIZE])
        for callback, val in zip(self.hdr_callbacks, hdr_vals):
            if callback is not None:
                accum = callback(accum, val)
        msg_size = (
            hdr_vals[self.size_idx]
            if self.size_idx is not None
            else len(data) if self.args else self.hdr.SIZE
        )
        return (
            self.parse_payload(
                accum,
                data[self.hdr.SIZE : msg_size],
                None if self.tag_idx is None else hdr_vals[self.tag_idx],
            ),
            data[(msg_size + 4 - 1) & ~(4 - 1) :],
        )

    def parse_payload(
        self, accum: Accum, data: bytes, tag: Optional[int] = None
    ) -> Accum:
        if self.dispatcher:
            while data:
                accum, data = self.dispatcher.parse(accum, data)
        return accum


class _Dispatcher(NllMsg):
    """Pseudo-msg which conditionally parses based on tag value."""

    def __init__(self, *args: NllMsg) -> None:
        assert args
        msg, *_ = args
        self.args = ()
        self.hdr = msg.hdr
        self.hdr_callbacks = msg.hdr_callbacks  # TODO: is this right?
        self.size_idx = msg.size_idx
        self.tag_idx = msg.tag_idx
        self.payload_parsers: Dict[Any, Callable[[Accum, bytes], Accum]] = {
            arg.tag: (
                (
                    lambda accum, data, arg=arg: (  # type: ignore
                        arg.resolve(accum).parse_payload(accum, data)
                    )
                )
                if isinstance(arg, NlaUnion)
                else arg.parse_payload
            )
            for arg in args
        }

    def parse_payload(
        self, accum: Accum, data: bytes, tag: Optional[int] = None
    ) -> Accum:
        return (
            self.payload_parsers[tag](accum, data)
            if tag in self.payload_parsers
            else accum
        )


class NllAttr(NllMsg):
    """Easier `rtattr` msg generation."""

    def __init__(
        self, tag: int, *args: NllMsg, size: Optional[int] = None
    ) -> None:
        self.tag = tag
        self.size = (
            2
            + 2
            + (size if size else len(b"".join(bytes(arg) for arg in args)))
        )
        super().__init__(
            rtattr(rta_type=tag if tag else 0, rta_len=self.size),
            *args,
            size_field="rta_len",
            tag_field="rta_type",
        )

    def __bytes__(self) -> bytes:
        return (
            super().__bytes__().ljust((self.size + 4 - 1) & ~(4 - 1), b"\0")
            if self.size > 4
            else b""
        )


class NlaUnion(NllAttr):
    """
    Some nested attributes (notably IFLA_INFO_DATA) have different
    contents depending on values contained in sibling attributes.
    This class allows for such differential parsing using values
    already in the accumulator object.
    """

    def __init__(self, tag: int, resolve: Callable[[Accum], NllMsg]) -> None:
        self.resolve = resolve
        super().__init__(tag)


class _NlaScalar(NllAttr, Generic[T]):
    """
    Scalar version of attribute.
    If serializing, user should provide val.
    If parsing, user can provide a callback,
    which can be used to populate accumulator or
    filter results by raising StopParsing.
    """

    def __init__(
        self,
        tag: int,
        val_or_callback: Optional[Union[T, Callable[[Accum, T], Accum]]],
    ) -> None:
        self.callback = val_or_callback if callable(val_or_callback) else None
        self.val = None if callable(val_or_callback) else val_or_callback
        super().__init__(
            tag=tag, size=0 if self.val is None else len(self.encode_payload())
        )

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}(tag={self.tag}, val={repr(self.val)})"
        )

    def __bytes__(self) -> bytes:
        return b"" if self.val is None else super().__bytes__()

    @abstractmethod
    def from_bytes(self, data: bytes) -> T:
        """Define decoding method and format."""

    def parse_payload(
        self, accum: Accum, data: bytes, tag: Optional[int] = None
    ) -> Accum:
        if not self.callback:
            return accum
        # mypy is upset that there are two separate Accum typevars
        # "Accum@__init__" and "Accum@parse", even though they
        # _really are_ expressing the same type...
        return self.callback(accum, self.from_bytes(data))  # type: ignore


class NlaStr(_NlaScalar[str]):
    def encode_payload(self) -> bytes:
        assert self.val is not None
        return self.val.encode("ascii") + b"\0"

    def from_bytes(self, data: bytes) -> str:
        return bytes(data).rstrip(b"\0").decode("ascii")


class _NlaInt(_NlaScalar[int]):
    BYTEORDER: Literal["big", "little"]
    PACKFMT: Literal["b", "h", "q", "i", "B", "H", "Q", "I"]

    def encode_payload(self) -> bytes:
        assert self.val is not None
        return pack(
            f"{'>' if self.BYTEORDER == 'big' else '<'}{self.PACKFMT}",
            self.val,
        )

    def from_bytes(self, data: bytes) -> int:
        return int.from_bytes(data, byteorder=self.BYTEORDER)


class NlaInt8(_NlaInt):
    BYTEORDER = byteorder
    PACKFMT = "b"


class NlaUInt8(_NlaInt):
    BYTEORDER = byteorder
    PACKFMT = "B"


class NlaInt16(_NlaInt):
    BYTEORDER = byteorder
    PACKFMT = "h"


class NlaBe16(_NlaInt):
    BYTEORDER = "big"
    PACKFMT = "H"


class NlaUInt16(_NlaInt):
    BYTEORDER = byteorder
    PACKFMT = "H"


class NlaUBe16(_NlaInt):
    BYTEORDER = "big"
    PACKFMT = "H"


class NlaInt32(_NlaInt):
    BYTEORDER = byteorder
    PACKFMT = "i"


class NlaBe32(_NlaInt):
    BYTEORDER = "big"
    PACKFMT = "i"


class NlaUInt32(_NlaInt):
    BYTEORDER = byteorder
    PACKFMT = "I"


class NlaUBe32(_NlaInt):
    BYTEORDER = "big"
    PACKFMT = "I"


class NlaInt64(_NlaInt):
    BYTEORDER = byteorder
    PACKFMT = "q"


class NlaBe64(_NlaInt):
    BYTEORDER = "big"
    PACKFMT = "q"


class NlaUInt64(_NlaInt):
    BYTEORDER = byteorder
    PACKFMT = "Q"


class NlaUBe64(_NlaInt):
    BYTEORDER = "big"
    PACKFMT = "Q"


class _NlaIp(_NlaScalar[str]):
    def encode_payload(self) -> bytes:
        assert self.val is not None
        return ip_address(self.val).packed


class NlaIp4(_NlaIp):
    def from_bytes(self, data: bytes) -> str:
        return str(IPv4Address(int.from_bytes(data, byteorder="big")))


class NlaIp6(_NlaIp):
    def from_bytes(self, data: bytes) -> str:
        return str(IPv6Address(int.from_bytes(data, byteorder="big")))


class NlaMac(_NlaScalar[str]):
    def encode_payload(self) -> bytes:
        assert self.val is not None
        return pack("BBBBBB", *(int(i, 16) for i in self.val.split(":")))

    def from_bytes(self, data: bytes) -> str:
        if len(data) != 6:
            # Some interfaces (tun type for instance) include mac
            # attribute with empty payload. Let user decide
            # if they are interested.
            return ""
        return ":".join(f"{i:02x}" for i in unpack("BBBBBB", data))


############################################################


def _messages(sk: socket) -> Iterator[Tuple[int, int, int, int, bytes]]:
    """
    Iterator to return sequence of nl messages read from the socket.
    Netlink uses datagram sockets, so messages are received whole.
    Python `recv` may bundle several (full) messages together.
    """
    while True:
        try:
            buf = memoryview(sk.recv(65536))
        # Non-blocking socket has no data available.
        except BlockingIOError:
            return
        if not buf:
            return
        while buf:
            msg_len, msg_type, flags, seq, pid = unpack(
                nlmsghdr.PACKFMT, buf[: nlmsghdr.SIZE]
            )
            if msg_type == NLMSG_DONE:
                return
            yield (
                msg_type,
                flags,
                seq,
                pid,
                buf[nlmsghdr.SIZE : msg_len],
            )
            buf = buf[msg_len:]


def _nll_send(
    sk: socket,
    rtgenmsg: bytes,
    rtyp: int,
) -> Iterator[bytes]:
    """
    Run netlink "dump" opeartion.
    """
    try:
        rc = sk.sendto(rtgenmsg, (0, 0))
    except OSError as e:
        raise NllError(e) from e
    if rc < 0:
        raise NllError(f"netlink send rc={rc}")
    dump_interrupted = False
    for msg_type, flags, seq, pid, message in _messages(sk):
        if msg_type == NLMSG_NOOP:
            # print("no-op")
            continue
        if msg_type == NLMSG_ERROR:
            code = NllMsg(nlmsgerr(error=lambda _, v: v)).parse(0, message)[0]
            if code:
                raise NllError(code, f"{rtgenmsg!r}: {strerror(-code)}")
            yield b""  # "no error" response to state-modifying requests
            continue
        if msg_type != rtyp:
            raise NllError(f"{msg_type} is not {rtyp}: {message.hex()}")
        if flags & NLM_F_DUMP_INTR:
            dump_interrupted = True  # and continue reading
        yield message
    if dump_interrupted:
        raise NllDumpInterrupted()  # raise this instead of StopIteration


def nll_get_dump(
    typ: int,
    rtyp: int,
    rtgenmsg: NllMsg,
    accum: Callable[[], Accum],
    parser: Callable[[Accum, bytes], Tuple[Accum, bytes]],
    sk: Optional[socket] = None,
) -> Iterator[Accum]:
    """
    Run netlink "dump" opeartion.
    typ  - netlink message type in nlmsghdr
    rtyp - expected return message type in nlmsghdr
    rtgenmsg - request message to be sent
    accum - constructor for accumulator object to be used during parsing
    parser - callable to consume incoming messages and populate accumulator
    """

    def _parse(dump: Iterator[bytes]) -> Iterator[Accum]:
        for msg in dump:
            try:
                yield parser(accum(), msg)[0]
            except StopParsing:
                continue

    msg = bytes(
        nlmsghdr(
            nlmsg_len=nlmsghdr.SIZE + len(bytes(rtgenmsg)),
            nlmsg_type=typ,
            nlmsg_flags=NLM_F_REQUEST | NLM_F_DUMP,
            nlmsg_seq=1,
            nlmsg_pid=getpid(),
        )
    ) + bytes(rtgenmsg)

    if sk is None:
        with socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE) as owns:
            owns.setsockopt(SOL_NETLINK, NETLINK_GET_STRICT_CHK, 1)
            yield from _parse(_nll_send(owns, msg, rtyp))
    else:
        yield from _parse(_nll_send(sk, msg, rtyp))


def nll_transact(
    typ: int,
    rtyp: int,
    rtgenmsg: NllMsg,
    sk: Optional[socket] = None,
    flags: int = 0,
) -> bytes:
    """
    Send message and receive response.
    Args same as nll_dump except for optional additional flags
    for nlmsghdr construction. Returns raw message bytes
    which can be parsed on the user side.
    """

    msg = bytes(
        nlmsghdr(
            nlmsg_len=nlmsghdr.SIZE + len(bytes(rtgenmsg)),
            nlmsg_type=typ,
            nlmsg_flags=NLM_F_REQUEST | NLM_F_ACK | flags,
            nlmsg_seq=1,
            nlmsg_pid=getpid(),
        ),
    ) + bytes(rtgenmsg)

    if sk is None:
        with socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE) as owns:
            return next(_nll_send(owns, msg, rtyp))
    return next(_nll_send(sk, msg, rtyp))


############################################################


def nll_make_event_listener(*groups: int, block: bool = False) -> socket:
    """
    Create socket bound to given groups, for use with `nll_get_events`.
    Sockets created with `block=False` will only produce output
    if a read is ready and should be used with select/poll.
    Sockets created with `block=True` will produce an endless
    blocking iterator which yields events as they become ready.
    """
    sock = socket(
        AF_NETLINK,
        SOCK_RAW | (0 if block else SOCK_NONBLOCK),
        NETLINK_ROUTE,
    )
    sock.bind((0, reduce(lambda x, y: x | y, groups)))
    return sock


def nll_listen(
    accum_parser: Dict[
        int,
        Tuple[
            Callable[[], Accum],
            Callable[[Accum, bytes], Accum],
        ],
    ],
    sk: socket,
) -> Iterable[Tuple[int, Any]]:
    """
    Fetch and parse messages of given types.
    `sk` should already be bound to correct groups.
    See `nll_make_event_listener.`
    """
    for msg_type, _, _, _, message in _messages(sk):
        try:
            accum, parser = accum_parser[msg_type]
        except KeyError:
            raise NllError(f"No parser for message type {msg_type}")
        yield (msg_type, parser(accum(), message)[0])  # type: ignore
