# Netlinklib - speed-optimised netlink operations in Python

This library is basically an alternative to
[pyroute2](https://github.com/svinota/pyroute2/),
only _much_ more rudimentary, but also significantly faster.

## Motivation

The problem with pure Python impementation of netlink "dump" operations
is that on a system with many kernel objects in the dump (such as routes,
or neighbour cache elements), parsing all the messages in the dump becomes
quite expensive.

Our answer to this challenge is to _not_ parse elements of the messages
that we don't need.

## Implementation

The high level, user visible, API should be considered a work in progress.
Just the functions that were needed for a particular bigger project are
implemented.  Whereas the low level API is where the speed magic comes to
life.

The idea is to allow a user-supplied collector function run over each of
the TLAs of the message and update an accumulator object on the way. TLAs
that the user don't need will be jumped over without parsing them. Nested
TLAs will be descended into only if the collector function decides that
it is necessary (and supplies a new collector function for the nested
elements).

User visible API and examples of "collector functions" reside in the "glue"
module, `__init__.py`. Low level parser infrastructure - in the `core.py`
module.

## Extra features and missing features

This package includes a builder helper in `mknetlinkdefs`: a program that
partially parses netlink related header files from Linux kernel and converts
structs, enums and defines into variable and class definitions in a
generated Python module. This allows us to use the same names that are used
in the C code that deals with netlink objects. The process is somewhat flaky,
but mostly works.

The program is usually run by `setup.py` but can be manually initiated via
the `Makefile` in `mknetlinkdefs`.

Unfortunately, kernel code does not contain information about the type
of NLA values of netlink messages. Dealing with the interpretation of the
byte values of NLAs has to be left to be hardcoded in the high level API
functions (or supplied by the end user).

## High Level API

TBD. Refer to the code in the `__init__.py` module in the meantime.
