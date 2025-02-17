""" Netlink dump implementation replacement for pyroute2 """

from socket import (
    AF_BRIDGE,
    socket,
)
from typing import (
    Any,
    Dict,
    Iterable,
    Optional,
    Union,
)
from .legacy_classes import (
    ndmsg,
)

# pylint: disable=wildcard-import, unused-wildcard-import
from .legacy_core import *
from .legacy_datatypes import *
from .defs import *
from .parser_neigh import newneigh_parser

from .deprecate import deprecated

__all__ = ("nll_get_neigh",)


@deprecated
def nll_get_neigh(
    socket: Optional[socket] = None,  # pylint: disable=redefined-outer-name
    family: int = AF_BRIDGE,
    **kwargs: Any,
) -> Iterable[Dict[str, Union[str, int]]]:
    """Public function to get all ND cache"""
    return nll_get_dump(
        RTM_GETNEIGH,
        RTM_NEWNEIGH,
        ndmsg(ndm_family=family).bytes,
        (),
        newneigh_parser,
        sk=socket,
        **kwargs,
    )
