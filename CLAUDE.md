# netlinklib — High-Performance Netlink Library

## Overview

netlinklib is a speed-optimized alternative to pyroute2 for Linux netlink operations. Its core innovation is a **parser combinator DSL** that only parses the message attributes actually requested, making it significantly faster for dump operations on systems with many kernel objects.

**Language:** Python 3
**Build:** setuptools + Debian packaging + code generation from kernel headers
**Package:** `python3-netlinklib`
**Key consumers:** pbrtemgr, pbsdnmgr

## Supported Netlink Families

| Family | Module | Operations |
|--------|--------|------------|
| **Link (IFLA_\*)** | `api_link.py` / `parser_link.py` | Add/delete/query interfaces (dummy, erspan, vrf, vxlan) |
| **Route (RTA_\*)** | `api_route.py` / `parser_route.py` | Add/delete/query routes, multipath, IPv4/IPv6 |
| **Neighbor (NDA_\*)** | `api_neigh.py` / `parser_neigh.py` | Query ARP/ND neighbor cache |
| **Traffic Control (TCA_\*)** | `api_tc.py` / `parser_tc.py` | Qdisc/class/filter management (HTB, prio, u32, flow) |

## API — Two Generations

### New Core API (core.py) — Recommended

Parser combinator approach with custom accumulators:

```python
from netlinklib import NllMsg, NllAttr, NlaStr, nll_get_dump

# Define parser for the attributes you need
parser = NllMsg(ifinfomsg(), NllAttr(IFLA_IFNAME, NlaStr("ifname")))

# Run dump with custom accumulator
for result in nll_get_dump(RTM_GETLINK, RTM_NEWLINK, NllMsg(ifinfomsg()), MyAccum, parser.parse):
    print(result)
```

**Key types:**
- `NllMsg(hdr, *args)` — Message with header + payload attributes
- `NllAttr(tag, *args)` — rtattr-wrapped attribute
- `NlaUnion(tag, resolve=fn)` — Conditional attribute (content depends on sibling value)
- Scalar types: `NlaStr`, `NlaIp4`, `NlaIp6`, `NlaMac`, `NlaInt32`, `NlaBe32`, etc.

**Key functions:**
- `nll_get_dump(typ, rtyp, msg, accum, parser)` — Dump with selective parsing
- `nll_transact(typ, rtyp, msg)` — Send message, receive response
- `nll_make_event_listener(*groups)` — Create socket for netlink events
- `nll_listen(accum_parser, sk)` — Parse incoming netlink events

### Legacy API (api_*.py) — Deprecated but widely used

Higher-level functions with full message parsing:

```python
from netlinklib import nll_get_links, nll_link_add, nll_get_routes, nll_route_add

links = list(nll_get_links())
routes = list(nll_get_routes(family=AF_INET))
nll_link_add(name="vrf100", kind="vrf", vrf_table=100)
nll_route_add(family=AF_INET, dst="10.0.0.0/24", gateway="192.168.1.1")
```

## Source Code Structure

```
netlinklib/
├── __init__.py          # Re-exports all public APIs
├── core.py              # Parser combinator core (NllMsg, NllAttr, nll_get_dump, etc.)
├── api_link.py          # High-level link API (deprecated)
├── api_route.py         # High-level route API (deprecated)
├── api_neigh.py         # High-level neighbor API (deprecated)
├── api_tc.py            # High-level traffic control API (deprecated)
├── parser_link.py       # Parser definitions for link messages
├── parser_route.py      # Parser definitions for route messages
├── parser_neigh.py      # Parser definitions for neighbor messages
├── parser_tc.py         # Parser definitions for TC messages
├── legacy_core.py       # Legacy parsing engine
├── legacy_datatypes.py  # Legacy data structures
├── defs.py              # AUTO-GENERATED: netlink constants (IFLA_*, RTA_*, TCA_*, etc.)
├── classes.py           # AUTO-GENERATED: struct wrappers (ifinfomsg, rtmsg, etc.)
├── legacy_classes.py    # AUTO-GENERATED: legacy struct wrappers
├── deprecate.py         # Deprecation decorator
├── __main__.py          # CLI profiling tool
└── py.typed             # PEP 561 type marker

mknetlinkdefs/
├── mknetlinkdefs.py     # Parses Linux kernel headers → Python code
└── Makefile             # Builds defs.py, classes.py, legacy_classes.py
```

## Code Generation

`mknetlinkdefs/` generates Python constants and struct wrappers from Linux kernel headers:

1. Runs C preprocessor on `linux/rtnetlink.h`, `linux/if_link.h`, `linux/pkt_sched.h`, etc.
2. Parses struct definitions, enums, and `#define` macros
3. Generates `defs.py` (constants), `classes.py` (struct wrappers), `legacy_classes.py`

## Exceptions

- `NllError` — General netlink error
- `NllDumpInterrupted` — Kernel signaled dump was interrupted (`NLM_F_DUMP_INTR`)
- `StopParsing` — Raised during parsing to exclude current message from results

## Dependencies

**Runtime:** Python 3.5+ standard library only (socket, struct, ipaddress)
**Build:** python3-pyparsing, linux-libc-dev, cpp (C preprocessor)
