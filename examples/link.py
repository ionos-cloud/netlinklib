from functools import partial
from ipaddress import ip_address
from socket import socket
from typing import Any, Callable, List, Optional, Sequence, Tuple, TypeVar

from netlinklib import *


IFF_UP = 1

Accum = TypeVar("Accum")


class LinkAccum:
    __slots__ = (
        "family",
        "index",
        "is_up",
        "name",
        "peer",
        "master",
        "kind",
        "krt",
        "erspan_ver",
        "gre_ikey",
        "gre_okey",
        "gre_local",
        "gre_remote",
        "gre_link",
    )

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}("
            + ", ".join(
                f"{k}={repr(getattr(self, k))}"
                for k in self.__slots__
                if hasattr(self, k)
            )
            + ")"
        )


def _set(
    key: str, transform: Callable[[Any], Any] = lambda x: x
) -> Callable[[Accum, Any], Accum]:
    def _setattr(accum: Accum, val: Any) -> Accum:
        setattr(accum, key, transform(val))
        return accum

    return _setattr


class NlaNestByKind(NlaNest):
    def __init__(
        self,
        tag: int,
        *nlas: NlaAttr,
        required: bool = False,
        **kinds: Sequence[NlaAttr],
    ) -> None:
        def _callback(data: bytes) -> None:
            self.nlas.append(
                NlaNest(
                    IFLA_INFO_DATA,
                    *kinds.get(NlaStr(IFLA_INFO_KIND).from_bytes(data), ()),
                )
            )

        super().__init__(
            tag,
            *nlas,
            required=required,
            callbacks={IFLA_INFO_KIND: _callback},
        )


def erspan_attrs(
    erspan_ver: Optional[int] = None,
    gre_link: Optional[int] = None,
    gre_ikey: Optional[int] = None,
    gre_okey: Optional[int] = None,
) -> Tuple[NlaAttr, ...]:
    return (
        NlaInt32(IFLA_GRE_LINK, val=gre_link),
        NlaInt32(IFLA_GRE_IFLAGS, val=(GRE_SEQ | GRE_KEY)),
        NlaInt32(IFLA_GRE_OFLAGS, val=(GRE_SEQ | GRE_KEY)),
        NlaBe32(IFLA_GRE_IKEY, val=gre_ikey),
        NlaBe32(IFLA_GRE_OKEY, val=gre_okey),
        NlaInt32(IFLA_GRE_ERSPAN_VER, val=erspan_ver),
    )


def erspan4_attrs(
    gre_local: Optional[str] = None,
    gre_remote: Optional[str] = None,
    **kwargs: Any,
) -> Tuple[NlaAttr, ...]:
    return (
        NlaStr(IFLA_INFO_KIND, val="erspan"),
        NlaNest(
            IFLA_INFO_DATA,
            *erspan_attrs(**kwargs),
            NlaIp4(IFLA_GRE_LOCAL, val=gre_local),
            NlaIp4(IFLA_GRE_REMOTE, val=gre_remote),
        ),
    )


def erspan6_attrs(
    gre_local: Optional[str] = None,
    gre_remote: Optional[str] = None,
    **kwargs: Any,
) -> Tuple[NlaAttr, ...]:
    return (
        NlaStr(IFLA_INFO_KIND, val="ip6erspan"),
        NlaNest(
            IFLA_INFO_DATA,
            *erspan_attrs(**kwargs),
            NlaIp6(IFLA_GRE_LOCAL, val=gre_local),
            NlaIp6(IFLA_GRE_REMOTE, val=gre_remote),
        ),
    )


def vrf_attrs(krt: Optional[int] = None) -> Tuple[NlaAttr, ...]:
    return (
        NlaStr(IFLA_INFO_KIND, val="vrf"),
        NlaNest(IFLA_INFO_DATA, NlaInt32(IFLA_VRF_TABLE, val=krt)),
    )


def vxlan_attrs(
    vxlan_id: Optional[int] = None,
    vxlan_local: Optional[int] = None,
    vxlan_learning: Optional[bool] = None,
    vxlan_port: Optional[int] = None,
) -> Tuple[NlaAttr, ...]:
    return (
        NlaStr(IFLA_INFO_KIND, val="vxlan"),
        NlaNest(
            NlaInt32(IFLA_VXLAN_ID, val=vxlan_id),
            NlaIp4(IFLA_VXLAN_LOCAL, val=vxlan_local),
            NlaInt32(IFLA_VXLAN_LEARNING, val=vxlan_learning),
            NlaInt32(IFLA_VXLAN_PORT, val=vxlan_port),
        ),
    )


def link_attrs(
    ifindex: int = 0,
    up: bool = False,
    name: Optional[str] = None,
    kind: Optional[str] = None,
    peer: Optional[int] = None,
    master: Optional[int] = None,
    **kwargs: Any,
) -> NlaStruct:
    return NlaStruct(
        ifinfomsg(ifi_index=ifindex, ifi_flags=IFF_UP if up else 0),
        NlaStr(IFLA_IFNAME, val=name),
        NlaInt32(IFLA_LINK, val=peer),
        NlaInt32(IFLA_MASTER, val=master),
        NlaNest(
            IFLA_LINKINFO,
            *(
                erspan4_attrs(**kwargs) if kind == "erspan"
                else erspan6_attrs(**kwargs) if kind == "ip6erspan"
                else vrf_attrs(**kwargs) if kind == "vrf"
                else vxlan_attrs(**kwargs) if kind == "vxlan"
                else ()
            ),
        ),
    )


def _link(
    msg_type: int,
    sk: Optional[socket] = None,
    parser: Optional[Callable[[bytes], Accum]] = None,
    **kwargs: Any,
) -> Optional[Accum]:
    return (parser if parser is not None else lambda msg: None)(
        nll_transact(
            msg_type,
            msg_type,
            link_attrs(**kwargs).to_bytes(),
            sk=sk,
            flags=NLM_F_CREATE | (NLM_F_ECHO if parser else 0),
        )
    )


link_add = partial(
    _link,
    RTM_NEWLINK,
    parser=lambda msg: ifinfomsg(msg).ifi_index if msg else None
)
link_del = partial(_link, RTM_DELLINK)


def get_links(
    nameonly: bool = False,
    sk: Optional[socket] = None,
) -> List[LinkAccum]:
    if nameonly:
        parser = NlaStruct(
            ifinfomsg(
                setters={
                    "ifi_index": _set("index"),
                    "ifi_flags": _set(
                        "is_up",
                        transform=lambda v: bool(v & IFF_UP),
                    ),
                }
            ),
            NlaStr(IFLA_IFNAME, setter=_set("name"))
        )
    else:
        parser = NlaStruct(
            ifinfomsg(
                setters={
                    "ifi_index": _set("index"),
                    "ifi_flags": _set(
                        "is_up",
                        transform=lambda v: bool(v & IFF_UP),
                    ),
                },
            ),
            NlaStr(IFLA_IFNAME, setter=_set("name")),
            NlaInt32(IFLA_LINK, setter=_set("peer")),
            NlaInt32(IFLA_MASTER, setter=_set("master")),
            NlaNestByKind(
                IFLA_LINKINFO,
                NlaStr(IFLA_INFO_KIND, setter=_set("kind")),
                vrf=(NlaInt32(IFLA_VRF_TABLE, setter=_set("krt")),),
                erspan=(
                    *(
                        erspan_attrs := (
                            NlaInt32(
                                IFLA_GRE_ERSPAN_VER,
                                setter=_set("erspan_ver"),
                            ),
                            NlaBe32(IFLA_GRE_IKEY, setter=_set("gre_ikey")),
                            NlaBe32(IFLA_GRE_OKEY, setter=_set("gre_okey")),
                            NlaInt32(IFLA_GRE_LINK, setter=_set("gre_link")),
                        )
                    ),
                    NlaIp4(IFLA_GRE_LOCAL, setter=_set("gre_local")),
                    NlaIp4(IFLA_GRE_REMOTE, setter=_set("gre_remote")),
                ),
                ip6erspan=(
                    *erspan_attrs,
                    NlaIp6(IFLA_GRE_LOCAL, setter=_set("gre_local")),
                    NlaIp6(IFLA_GRE_REMOTE, setter=_set("gre_remote")),
                ),
            ),
        )
    return list(
        nll_get_dump(
            RTM_GETLINK,
            RTM_NEWLINK,
            NlaStruct(ifinfomsg()).to_bytes(),
            lambda: LinkAccum(),
            parser.parse,
            sk=sk,
        )
    )


if __name__ == "__main__":
    from pprint import pprint

    try:
        pprint(
            link_add(
                name="myersp",
                up=True,
                kind="ip6erspan",
                gre_link=link_add(
                    name="myvrf",
                    up=True,
                    kind="vrf",
                    krt=999,
                ),
                erspan_ver=1,
                gre_ikey=1,
                gre_okey=1,
                gre_local="::1",
                gre_remote="::2",
            )
        )
        # pprint(
        #     link_add(
        #         name="myvxlan",
        #         up=True,
        #         kind="vxlan",
        #         vxlan_id=1,
        #         vxlan_local=None,
        #         vxlan_learning=None,
        #         vxlan_port=None,
        #     )
        # )
    finally:
        pprint(list(get_links()))
        link_del(name="myersp")
        link_del(name="myvrf")
        # link_del(name="myvxlan")
