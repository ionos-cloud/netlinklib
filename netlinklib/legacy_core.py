""" Netlink core functions for legacy API"""

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

from .legacy_datatypes import (
    NllError,
    NllDumpInterrupted,
    NllMsg,
    RtaDesc,
)
from .defs import *  # pylint: disable=wildcard-import, unused-wildcard-import
from .legacy_classes import nlmsgerr, nlmsghdr, rtattr  # type: ignore [attr-defined]

__all__ = (
    "iterate_rtalist",
    "nll_get_dump",
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


def _nll_get_dump(  # pylint: disable=too-many-locals
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


def nll_get_dump(
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
            yield from _nll_get_dump(
                owns, typ, rtyp, rtgenmsg, attrs, parser, **kwargs
            )
    else:
        yield from _nll_get_dump(
            sk, typ, rtyp, rtgenmsg, attrs, parser, **kwargs
        )


def _nll_transact(
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


def nll_transact(
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
            return _nll_transact(owns, typ, expect, rtgenmsg, attrs, nlm_flags)
    return _nll_transact(sk, typ, expect, rtgenmsg, attrs, nlm_flags)


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
