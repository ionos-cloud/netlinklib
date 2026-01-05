"""List of headers to process and related bits"""

INC = "/usr/include"
HEADERS = (
    "linux/if.h",
    "linux/if_addr.h",
    "linux/if_bridge.h",
    "linux/if_link.h",
    "linux/if_tunnel.h",
    "linux/netlink.h",
    "linux/genetlink.h",
    "linux/rtnetlink.h",
    "linux/neighbour.h",
    "linux/veth.h",
    "linux/ethtool.h",
    "linux/ethtool_netlink.h",
    "linux/pkt_sched.h",
    "linux/pkt_cls.h",
    "linux/tc_act/tc_bpf.h",
    "linux/tc_act/tc_connmark.h",
    "linux/tc_act/tc_csum.h",
    "linux/tc_act/tc_ct.h",
    "linux/tc_act/tc_ctinfo.h",
    "linux/tc_act/tc_defact.h",
    "linux/tc_act/tc_gact.h",
    "linux/tc_act/tc_gate.h",
    "linux/tc_act/tc_ife.h",
    "linux/tc_act/tc_mirred.h",
    "linux/tc_act/tc_mpls.h",
    "linux/tc_act/tc_nat.h",
    "linux/tc_act/tc_pedit.h",
    "linux/tc_act/tc_sample.h",
    "linux/tc_act/tc_skbedit.h",
    "linux/tc_act/tc_skbmod.h",
    "linux/tc_act/tc_tunnel_key.h",
    "linux/tc_act/tc_vlan.h",
    "linux/tc_ematch/tc_em_cmp.h",
    "linux/tc_ematch/tc_em_ipt.h",
    "linux/tc_ematch/tc_em_meta.h",
    "linux/tc_ematch/tc_em_nbyte.h",
    "linux/tc_ematch/tc_em_text.h",
)

PREINC = """#define __signed__
#define __attribute__(x)
#define __inline__ inline
#define __asm__(x)
"""

# These defines refer to other identifies, rather than arithmetic expressions
# or strings. We have not good way to detect such cases automatically.
EXCL_DEFS = {
    "ifc_buf",
    "ifc_req",
    "ifr_addr",
    "ifr_bandwidth",
    "ifr_broadaddr",
    "ifr_data",
    "ifr_dstaddr",
    "ifr_flags",
    "ifr_hwaddr",
    "ifr_ifindex",
    "ifr_map",
    "ifr_metric",
    "ifr_mtu",
    "ifr_name",
    "ifr_netmask",
    "ifr_newname",
    "ifr_qlen",
    "ifr_settings",
    "ifr_slave",
    "tcm_block_index",
    "tc_gen",
    "tc_pedit",
}
