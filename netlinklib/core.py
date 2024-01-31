""" Netlink dump implementation core functions """

from os import getpid
from socket import AF_NETLINK, NETLINK_ROUTE, SOCK_RAW, socket
from sys import byteorder
from typing import (
    Any,
    Callable,
    Dict,
    Iterable,
    Optional,
    Tuple,
    TypeVar,
    Union,
)
from ipaddress import IPv4Address, IPv6Address, ip_address

from .datatypes import NllError, NllDumpInterrupted, RtaDesc
from .defs import *  # pylint: disable=wildcard-import, unused-wildcard-import
from .classes import nlmsghdr, rtattr

__all__ = "nll_get_dump", "parse_rtalist", "to_str", "to_int", "to_ipaddr"


def _messages(sk: socket) -> Iterable[Tuple[int, int, int, int, bytes]]:
    """Iterator to return sequence of nl messages read from the socket"""
    buf = b""
    while True:
        if len(buf) < 16:
            buf += sk.recv(8192)
        if not buf:
            return
        datasize = len(buf)
        if datasize < 16:
            raise NllError(f"Short read {datasize}: {buf.hex()}")
        mh = nlmsghdr(buf[:16])
        if datasize < mh.nlmsg_len:
            raise NllError(
                f"data size {datasize} less then msg_len {mh.nlmsg_len}:"
                f" {buf.hex()}"
            )
        if mh.nlmsg_type == NLMSG_DONE:
            return
        message = buf[16 : mh.nlmsg_len]
        buf = buf[mh.nlmsg_len :]
        yield (
            mh.nlmsg_type,
            mh.nlmsg_flags,
            mh.nlmsg_seq,
            mh.nlmsg_pid,
            message,
        )


Rtype = TypeVar("Rtype")


def _nll_get_dump(  # pylint: disable=too-many-locals
    s: socket,
    typ: int,
    rtyp: int,
    rtgenmsg: bytes,
    parser: Callable[[bytes], Rtype],
    **kwargs: Any,
) -> Iterable[Rtype]:
    """
    Run netlink "dump" opeartion.
    """
    pid = getpid()
    seq = 1
    flags = NLM_F_REQUEST | NLM_F_DUMP
    size = 4 + 2 + 2 + 4 + 4 + len(rtgenmsg)
    nlhdr = nlmsghdr(
        nlmsg_len=size,
        nlmsg_type=typ,
        nlmsg_flags=flags,
        nlmsg_seq=seq,
        nlmsg_pid=pid,
    ).bytes
    try:
        rc = s.sendto(nlhdr + rtgenmsg, (0, 0))
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
        raise NllDumpInterrupted  # raise this instead of StopIteration


def nll_get_dump(
    typ: int,
    rtyp: int,
    rtgenmsg: bytes,
    parser: Callable[[bytes], Rtype],
    sk: Optional[socket] = None,
    **kwargs: Any,
) -> Iterable[Rtype]:
    """
    Run netlink "dump" opeartion.
    """
    if sk is None:
        with socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE) as owns:
            for x in _nll_get_dump(
                owns, typ, rtyp, rtgenmsg, parser, **kwargs
            ):
                yield x
            return None  # solely to make pylint happy
    else:
        return _nll_get_dump(sk, typ, rtyp, rtgenmsg, parser, **kwargs)


#######################################################################


Accum = TypeVar("Accum")


def to_str(
    accum: Dict[str, Union[int, str]], data: bytes, key: str
) -> Dict[str, Union[int, str]]:
    """Accumulating function that saves a string"""
    accum[key] = data.rstrip(b"\0").decode("ascii")
    return accum


def to_int(
    accum: Dict[str, Union[int, str]], data: bytes, key: str
) -> Dict[str, Union[int, str]]:
    """Accumulating function that saves an integer"""
    accum[key] = int.from_bytes(data, byteorder=byteorder)
    return accum


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


def parse_rtalist(accum: Accum, data: bytes, sel: RtaDesc) -> Accum:
    """Walk over a chunk with collection of RTAs and collect RTAs"""
    while data:
        if len(data) < 4:
            raise NllError(f"data len {len(data)} < 4: {data.hex()}")
        rta = rtattr(data[:4])
        if rta.rta_len < 4:
            raise NllError(f"rta_len {rta.rta_len} < 4: {data.hex()}")
        rta_data = data[4 : rta.rta_len]
        increment = (rta.rta_len + 4 - 1) & ~(4 - 1)
        if len(data) < increment:
            raise NllError(f"data len {len(data)} < {increment}: {data.hex()}")
        data = data[increment:]
        if rta.rta_type in sel:
            op, *args = sel[rta.rta_type]
            accum = op(accum, rta_data, *args)
    return accum


############################################################
