""" Netlink dump implementation replacement for pyroute2 """

from functools import reduce
from socket import (
    AF_NETLINK,
    NETLINK_ROUTE,
    SOCK_NONBLOCK,
    SOCK_RAW,
    socket,
)
from typing import (
    Any,
    Callable,
    Dict,
    Iterable,
    Tuple,
)

# pylint: disable=wildcard-import, unused-wildcard-import
from .core import *
from .datatypes import *
from .defs import *

# newaddr_parser,
from .parser_link import newlink_parser
from .parser_neigh import newneigh_parser
from .parser_route import newroute_parser


_SUPPORTED_GROUPS = {
    # RTMGRP_IPV4_IFADDR,
    # RTMGRP_IPV6_IFADDR,
    RTMGRP_IPV4_ROUTE: (RTM_NEWROUTE, RTM_DELROUTE),
    RTMGRP_IPV6_ROUTE: (RTM_NEWROUTE, RTM_DELROUTE),
    RTMGRP_NEIGH: (RTM_NEWNEIGH, RTM_DELNEIGH),
    RTMGRP_LINK: (RTM_NEWLINK, RTM_DELLINK),
}


_SUPPORTED_EVENTS: Dict[int, Callable[[bytes], Any]] = {
    # TODO: Add new parsers  # pylint: disable=fixme
    # RTM_NEWADDR: newaddr_parser,
    # RTM_DELADDR: newaddr_parser,
    RTM_NEWLINK: newlink_parser(),
    RTM_DELLINK: newlink_parser(),
    RTM_NEWNEIGH: newneigh_parser,
    RTM_DELNEIGH: newneigh_parser,
    RTM_NEWROUTE: newroute_parser,
    RTM_DELROUTE: newroute_parser,
}


def nll_make_event_listener(*groups: int, block: bool = False) -> socket:
    """
    Create socket bound to given groups, for use with `nll_get_events`.
    If no groups are given, subscribe to all supported groups.
    Sockets created with `block=False` will only produce output
    if a read is ready and should be used with select/poll.
    Sockets created with `block=True` will produce an endless
    blocking iterator which yields events as they become ready.
    """
    unsupported = set(groups) - set(_SUPPORTED_GROUPS)
    if unsupported:
        raise NllError(f"Unsupported group(s) requested: {unsupported}")
    sock = socket(
        AF_NETLINK, SOCK_RAW | (0 if block else SOCK_NONBLOCK), NETLINK_ROUTE
    )
    sock.bind(
        (
            0,
            reduce(
                lambda x, y: x | y, groups if groups else _SUPPORTED_GROUPS
            ),
        )
    )
    return sock


def nll_get_events(sk: socket) -> Iterable[Tuple[int, Any]]:
    """
    Socket should already be bound to correct multicast group addr.
    If `events` are given, only parse and return matching events.
    """
    return nll_handle_event(_SUPPORTED_EVENTS, sk)
