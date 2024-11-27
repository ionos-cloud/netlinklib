""" Netlink dump implementation core functions """

from abc import abstractmethod
from collections import ChainMap
from functools import partial
from os import getpid, strerror
from socket import AF_NETLINK, NETLINK_ROUTE, SOCK_RAW, socket
from struct import error as StructError, pack
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
)
from ipaddress import IPv4Address, IPv6Address, ip_address

from .datatypes import (
    NllError,
    NllDumpInterrupted,
    NllMsg,
    RtaDesc,
    StopParsing,
)
from .defs import *  # pylint: disable=wildcard-import, unused-wildcard-import
from .classes import nlmsgerr, nlmsghdr, rtattr  # type: ignore [attr-defined]

__all__ = (
    "NlaAttr",
    "NlaBe32",
    "NlaInt",
    "NlaIp",
    "NlaNest",
    "NlaStruct",
    "NlaStr",
    "iterate_rtalist",
    "legacy_nll_get_dump",
    "legacy_nll_transact",
    "nll_get_dump",
    "nll_handle_event",
    "nll_transact",
    "parse_rtalist",
    "pack_attr",
    "to_true",
    "to_str",
    "to_int",
    "to_int_be",
    "to_ipaddr",
    "to_mac",
)

SOL_NETLINK = 270

Accum = TypeVar("Accum")


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
            mh = nlmsghdr(buf)
            if mh.nlmsg_type == NLMSG_DONE:
                return
            buf = buf[mh.nlmsg_len :]
            yield (
                mh.nlmsg_type,
                mh.nlmsg_flags,
                mh.nlmsg_seq,
                mh.nlmsg_pid,
                mh.remainder[: mh.nlmsg_len - nlmsghdr.SIZE],
            )


Rtype = TypeVar("Rtype")


def pack_attr(tag: int, val: bytes) -> bytes:
    size = 2 + 2 + len(val)
    increment = (size + 4 - 1) & ~(4 - 1)
    return (rtattr(rta_len=size, rta_type=tag).bytes + val).ljust(
        increment, b"\0"
    )


def _legacy_nll_get_dump(  # pylint: disable=too-many-locals
    s: socket,
    typ: int,
    rtyp: int,
    rtgenmsg: bytes,
    attrs: Sequence[Tuple[int, bytes]],
    parser: Callable[[bytes], Rtype],
    **kwargs: Any,
) -> Iterable[Rtype]:
    """
    Run netlink "dump" opeartion.
    """
    pid = getpid()
    seq = 1
    flags = NLM_F_REQUEST | NLM_F_DUMP
    battrs = b"".join(pack_attr(k, v) for k, v in attrs)
    size = nlmsghdr.SIZE + len(rtgenmsg) + len(battrs)
    nlhdr = nlmsghdr(
        nlmsg_len=size,
        nlmsg_type=typ,
        nlmsg_flags=flags,
        nlmsg_seq=seq,
        nlmsg_pid=pid,
    ).bytes
    try:
        rc = s.sendto(nlhdr + rtgenmsg + battrs, (0, 0))
    except OSError as e:
        raise NllError(e) from e
    if rc < 0:
        raise NllError(f"netlink send rc={rc}")
    dump_interrupted = False
    for msg_type, flags, seq, pid, message in _messages(s):
        if msg_type == NLMSG_NOOP:
            # print("no-op")
            continue
        if msg_type == NLMSG_ERROR:
            raise NllError(f"NLMSG_ERROR {flags} {seq} {pid}: {message.hex()}")
        if msg_type != rtyp:
            raise NllError(f"{msg_type} is not {rtyp}: {message.hex()}")
        if flags & NLM_F_DUMP_INTR:
            dump_interrupted = True  # and continue reading
        yield parser(message, **kwargs)
    if dump_interrupted:
        raise NllDumpInterrupted()  # raise this instead of StopIteration


def legacy_nll_get_dump(
    typ: int,
    rtyp: int,
    rtgenmsg: bytes,
    attrs: Sequence[Tuple[int, bytes]],
    parser: Callable[[bytes], Rtype],
    sk: Optional[socket] = None,
    **kwargs: Any,
) -> Iterable[Rtype]:
    """
    Run netlink "dump" opeartion.
    """
    if sk is None:
        with socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE) as owns:
            owns.setsockopt(SOL_NETLINK, NETLINK_GET_STRICT_CHK, 1)
            yield from _legacy_nll_get_dump(
                owns, typ, rtyp, rtgenmsg, attrs, parser, **kwargs
            )
    else:
        yield from _legacy_nll_get_dump(
            sk, typ, rtyp, rtgenmsg, attrs, parser, **kwargs
        )


def _legacy_nll_transact(
    sk: socket,
    typ: int,
    expect: int,
    rtgenmsg: bytes,
    attrs: Sequence[Tuple[int, bytes]],
    nlm_flags: int,
) -> bytes:
    # return message of the expected type as bytes (memoryview slice),
    # or b"" if the response was an nlmsgerr with error == 0,
    # or raise NllError exception.
    pid = getpid()
    seq = 0
    flags = NLM_F_REQUEST | NLM_F_ACK | nlm_flags
    battrs = b"".join(pack_attr(k, v) for k, v in attrs)
    size = nlmsghdr.SIZE + len(rtgenmsg) + len(battrs)
    nlhdr = nlmsghdr(
        nlmsg_len=size,
        nlmsg_type=typ,
        nlmsg_flags=flags,
        nlmsg_seq=seq,
        nlmsg_pid=pid,
    ).bytes
    try:
        rc = sk.sendto(nlhdr + rtgenmsg + battrs, (0, 0))
    except OSError as e:
        raise NllError(e) from e
    try:
        buf = sk.recv(65536)
    except OSError as e:
        raise NllError(e) from e
    mh = nlmsghdr(memoryview(buf))
    if mh.nlmsg_type == NLMSG_ERROR:
        emh = nlmsgerr(mh.remainder)
        if emh.error:
            raise NllError(
                emh.error, f"{nlhdr!r} with {attrs}: {strerror(-emh.error)}"
            )
        return b""  # "no error" response to state-modifying requests
    if mh.nlmsg_type != expect:
        raise NllError(f"Got {mh} instead of {expect}")
    return mh.remainder


def legacy_nll_transact(
    typ: int,
    expect: int,
    rtgenmsg: bytes,
    attrs: Sequence[Tuple[int, bytes]],
    sk: Optional[socket] = None,
    nlm_flags: int = 0,
) -> bytes:
    """Send message and receive response"""
    if sk is None:
        with socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE) as owns:
            return _legacy_nll_transact(
                owns, typ, expect, rtgenmsg, attrs, nlm_flags
            )
    return _legacy_nll_transact(sk, typ, expect, rtgenmsg, attrs, nlm_flags)


def nll_handle_event(
    parsers: Dict[int, Callable[[bytes], Any]],
    sk: socket,
) -> Iterable[Tuple[int, Any]]:
    """
    Fetch and parse messages of given types.
    """
    for msg_type, _, _, _, message in _messages(sk):
        try:
            yield (msg_type, parsers[msg_type](message))
        except KeyError:
            raise NllError(f"No parser for message type {msg_type}")


#######################################################################


def to_true(
    accum: Dict[str, Union[int, str]], data: bytes, key: str
) -> Dict[str, Union[int, str]]:
    """Accumulating function that does not check data"""
    accum[key] = True
    return accum


def to_str(
    accum: Dict[str, Union[int, str]], data: bytes, key: str
) -> Dict[str, Union[int, str]]:
    """Accumulating function that saves a string"""
    accum[key] = bytes(data).rstrip(b"\0").decode("ascii")
    return accum


def to_mac(
    accum: Dict[str, Union[int, str]], data: bytes, key: str
) -> Dict[str, Union[int, str]]:
    """Accumulating function that saves a string"""
    accum[key] = ":".join(f"{x:02x}" for x in data)
    return accum


def _to_int(
    accum: Dict[str, Union[int, str]],
    data: bytes,
    key: str,
    byteorder: Literal["little", "big"],
) -> Dict[str, Union[int, str]]:
    """Accumulating function that saves an integer"""
    accum[key] = int.from_bytes(data, byteorder=byteorder)
    return accum


to_int = partial(_to_int, byteorder=byteorder)
to_int_be = partial(_to_int, byteorder="big")


def to_ipaddr(
    accum: Dict[str, Union[int, str]], data: bytes, key: str
) -> Dict[str, Union[int, str]]:
    """Accumulating function that saves IP address in the form of s string"""
    size = len(data)
    address: Union[IPv4Address, IPv6Address]
    if size == 4:
        address = IPv4Address(int.from_bytes(data, byteorder="big"))
    elif size == 16:
        address = IPv6Address(int.from_bytes(data, byteorder="big"))
    else:
        # this is potentially less reliable, ints < 2**32 become IPv4
        address = ip_address(int.from_bytes(data, byteorder="big"))
    accum[key] = str(address)
    return accum


def iterate_rtalist(data: bytes) -> Iterator[Tuple[int, bytes]]:
    """Walk over a chunk with collection of RTAs and collect RTAs"""
    while data:
        try:
            rta = rtattr(data)
        except StructError as e:
            raise NllError(e) from e
        # if rta.rta_len < 4:
        #     raise NllError(f"rta_len {rta.rta_len} < 4: {data.hex()}")
        increment = (rta.rta_len + 4 - 1) & ~(4 - 1)
        # if len(data) < increment:
        #     raise NllError(f"data len {len(data)} < {increment}: {data.hex()}")
        data = data[increment:]
        yield rta.rta_type, rta.remainder[: rta.rta_len - rtattr.SIZE]


def parse_rtalist(accum: Accum, data: bytes, sel: RtaDesc) -> Accum:
    """Walk over a chunk with collection of RTAs and collect RTAs"""
    while data:
        try:
            rta = rtattr(data)
        except StructError as e:
            raise NllError(e) from e
        # if rta.rta_len < 4:
        #     raise NllError(f"rta_len {rta.rta_len} < 4: {data.hex()}")
        increment = (rta.rta_len + 4 - 1) & ~(4 - 1)
        # if len(data) < increment:
        #     raise NllError(f"data len {len(data)} < {increment}: {data.hex()}")
        data = data[increment:]
        if rta.rta_type in sel:
            op, *args = sel[rta.rta_type]
            accum = op(
                accum, rta.remainder[: rta.rta_len - rtattr.SIZE], *args
            )
    return accum


############################################################


def nlmsg(
    typ: int,
    flags: int,
    seq: int,
    payload: bytes,
) -> bytes:
    return (
        nlmsghdr(
            nlmsg_len=nlmsghdr.SIZE + len(payload),
            nlmsg_type=typ,
            nlmsg_flags=flags,
            nlmsg_seq=seq,
            nlmsg_pid=getpid(),
        ).bytes
        + payload
    )


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
            emh = nlmsgerr(message)
            if emh.error:
                raise NllError(
                    emh.error, f"{rtgenmsg!r}: {strerror(-emh.error)}"
                )
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
    rtgenmsg: bytes,
    accum: Callable[[], Accum],
    parser: Callable[[Accum, bytes], Accum],
    sk: Optional[socket] = None,
) -> Iterator[Accum]:
    """
    Run netlink "dump" opeartion.
    """

    def _parse(dump: Iterator[bytes]) -> Iterator[Accum]:
        for msg in dump:
            try:
                yield parser(accum(), msg)
            except StopParsing:
                continue

    msg = nlmsg(
        typ=typ,
        flags=NLM_F_REQUEST | NLM_F_DUMP,
        seq=1,
        payload=rtgenmsg,
    )
    if sk is None:
        with socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE) as owns:
            owns.setsockopt(SOL_NETLINK, NETLINK_GET_STRICT_CHK, 1)
            yield from _parse(_nll_send(owns, msg, rtyp))
    else:
        dump = _parse(_nll_send(sk, msg, rtyp))


def nll_transact(
    typ: int,
    rtyp: int,
    rtgenmsg: bytes,
    sk: Optional[socket] = None,
    flags: int = 0,
) -> bytes:
    """Send message and receive response"""
    msg = nlmsg(
        typ=typ,
        flags=NLM_F_REQUEST | NLM_F_ACK | flags,
        seq=1,
        payload=rtgenmsg,
    )
    if sk is None:
        with socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE) as owns:
            return next(_nll_send(owns, msg, rtyp))
    return next(_nll_send(sk, msg, rtyp))


############################################################


T = TypeVar("T")


class NlaType:
    @abstractmethod
    def parse(self, accum: Accum, data: bytes) -> Accum:
        """Fill and return accumulator object."""

    @abstractmethod
    def to_bytes(self) -> bytes:
        """Convert to byte representation."""


class NlaAttr(NlaType):
    """A netlink attribute. Is packed with `rtattr` header."""

    def __init__(
        self,
        *args: Any,
        tag: int = 0,
        required: bool = False,
        **kwargs: Any,
    ) -> None:
        self.tag = tag
        self.required = required
        super().__init__(*args, **kwargs)

    @abstractmethod
    def _bytes(self) -> bytes:
        """Define encoding method and format. Called by `bytes` method."""

    def to_bytes(self) -> bytes:
        val = self._bytes()
        size = 2 + 2 + len(val)
        increment = (size + 4 - 1) & ~(4 - 1)
        return (rtattr(rta_len=size, rta_type=self.tag).bytes + val).ljust(
            increment, b"\0"
        )


class _NlaScalar(NlaAttr, Generic[T]):
    """
    Scalar version of attribute.
    User must provide `val` value if the object
    is to be used as a serializer. If object
    is used a parser and `val` is provided, it
    serves as a filter, raising `StopParsing`
    if parsed value does not match user-provided one.
    TODO: We may wish to generalize this
    'accept/reject' parsed value concept, maybe
    using user provided callback instead...
    """

    ACCUM_REPR: Callable[[T], Any]

    def __init__(
        self,
        tag: int,
        *args: Any,
        val: Optional[T] = None,
        setter: Optional[Callable[[Accum, T], Accum]] = None,
        **kwargs: Any,
    ) -> None:
        self.val = val
        self.setter = setter
        super().__init__(*args, tag=tag, **kwargs)

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(tag={self.tag},val={self.val})"

    def to_bytes(self) -> bytes:
        if self.val is None:
            return b""
        return super().to_bytes()

    @abstractmethod
    def from_bytes(self, data: bytes) -> T:
        """Define decoding method and format."""

    def parse(self, accum: Accum, data: bytes) -> Accum:
        if self.setter is None:
            return accum
        parsed = self.from_bytes(data)
        if self.val is not None and self.val != parsed:
            raise StopParsing
        # mypy is upset that there are two separate Accum typevars
        # "Accum@__init__" and "Accum@parse", even though they
        # _really are_ expressing the same type...
        return self.setter(accum, self.ACCUM_REPR(parsed))  # type: ignore


class NlaStr(_NlaScalar[str]):
    ACCUM_REPR = str

    def _bytes(self) -> bytes:
        assert self.val is not None
        return self.val.encode("ascii") + b"\0"

    def from_bytes(self, data: bytes) -> str:
        return bytes(data).rstrip(b"\0").decode("ascii")


class _NlaInt(_NlaScalar[int]):
    BYTEORDER: Literal["big", "little"]
    ACCUM_REPR = int

    def _bytes(self) -> bytes:
        assert self.val is not None
        return pack(f"{'>' if self.BYTEORDER == 'big' else '<'}i", self.val)

    def from_bytes(self, data: bytes) -> int:
        return int.from_bytes(data, byteorder=self.BYTEORDER)


class NlaInt(_NlaInt):
    BYTEORDER = byteorder


class NlaBe32(_NlaInt):
    BYTEORDER = "big"


class NlaIp(_NlaScalar[Union[IPv4Address, IPv6Address]]):
    ACCUM_REPR = str

    def _bytes(self) -> bytes:
        assert self.val is not None
        return ip_address(self.val).packed

    def from_bytes(self, data: bytes) -> Union[IPv4Address, IPv6Address]:
        size = len(data)
        if size == 4:
            return IPv4Address(int.from_bytes(data, byteorder="big"))
        elif size == 16:
            return IPv6Address(int.from_bytes(data, byteorder="big"))
        raise ValueError(
            f"Received incorrect number of bytes "
            "({size}) for NlaIpaddr: {data}"
        )


class _NlaNest(NlaType):
    """Nested NLA list without tag (used as part of NlaStruct)"""

    def __init__(
        self,
        *nlas: NlaAttr,
        callbacks: Optional[Dict[int, Callable[[bytes], None]]] = None,
        **kwargs: Any,
    ) -> None:
        self.nlas = sorted(
            nlas,
            key=lambda nla: (
                # Parse "filter" objects first
                1
                if (isinstance(nla, _NlaScalar) and nla.val is not None)
                # Then decend into nested attributes
                else (
                    2
                    if isinstance(nla, _NlaNest)
                    # Then parse scalar attributes
                    else 3
                )
            ),
        )
        self.callbacks = {} if callbacks is None else callbacks
        super().__init__(**kwargs)

    def __repr__(self) -> str:
        return f"({','.join(nla.__repr__() for nla in self.nlas)})"

    def to_bytes(self) -> bytes:
        return b"".join(nla.to_bytes() for nla in self.nlas)

    def parse(self, accum: Accum, data: bytes) -> Accum:
        attrs: Dict[int, bytes] = {}
        while data:
            try:
                rta = rtattr(data)
            except StructError as e:
                raise NllError(e) from e
            increment = (rta.rta_len + 4 - 1) & ~(4 - 1)
            attrs[rta.rta_type] = rta.remainder[: rta.rta_len - rtattr.SIZE]
            data = data[increment:]
        # Delay any parsing, since self.has/no_val could
        # get altered by a callback.
        for tag, callback in self.callbacks.items():
            callback(attrs[tag])
        for nla in self.nlas:
            try:
                accum = nla.parse(accum, attrs[nla.tag])
            except KeyError:
                if getattr(nla, "val", None) is not None or nla.required:
                    raise StopParsing
        return accum


class NlaNest(NlaAttr, _NlaNest):
    """A nested NLA list with attribute header/tag."""

    def __init__(self, tag: int, *args: Any, **kwargs: Any) -> None:
        # Just so that it resembles the other NlaAttrs with tag first
        super().__init__(*args, tag=tag, **kwargs)

    def _bytes(self) -> bytes:
        return _NlaNest.to_bytes(self)


class NlaStruct(NlaType):
    """
    Used for top-level structs and members of
    lists of nested rtas (i.e. contents of RTA_MULTIPATH)
    """

    def __init__(self, struct: NllMsg, *nlas: NlaAttr, **kwargs: Any) -> None:
        self.struct = struct
        self.nlas = _NlaNest(*nlas)
        super().__init__(**kwargs)

    def to_bytes(self) -> bytes:
        return self.struct.bytes + self.nlas.to_bytes()

    def parse(self, accum: Accum, data: bytes) -> Accum:
        self.struct.parse(accum, data)
        self.nlas.parse(accum, data[self.struct.SIZE :])
        return accum

    @staticmethod
    def get_size(data: bytes) -> int:
        """
        Subclasses should define this if multiple NlaStructs
        are to be parsed (see NlaStructList).
        """
        return len(data)


class NlaStructRta(NlaAttr, NlaStruct):
    """TODO: Not sure if we have any of these."""

    def __init__(self, tag: int, *args: Any) -> None:
        super().__init__(*args, tag=tag)

    def _bytes(self) -> bytes:
        return super().to_bytes()


class NlaStructList(NlaAttr):
    """A list of struct+nested attr objects."""

    def __init__(self, tag: int, *structs: NlaStruct) -> None:
        # Struct lists should probably contain all the same type of struct
        assert len(set(type(s.struct) for s in structs)) == 1
        self.structs = structs
        super().__init__(tag=tag)

    def _bytes(self) -> bytes:
        return b"".join(s.to_bytes() for s in self.structs)

    def parse(self, accum: Accum, data: bytes) -> Accum:
        for struct in self.structs:
            size = struct.get_size(data)
            accum = struct.parse(accum, data[:size])
            data = data[size:]
        return accum
