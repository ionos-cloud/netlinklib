# Netlinklib - speed-optimized netlink operations in Python

This library is basically an alternative to
[pyroute2](https://github.com/svinota/pyroute2/),
only _much_ more rudimentary, but also significantly faster.

## Motivation

The problem with pure Python implementation of netlink "dump" operations
is that on a system with many kernel objects in the dump (such as routes,
or neighbor cache elements), parsing all the messages in the dump becomes
quite expensive.

Our answer to this challenge is to _not_ parse elements of the messages
that we don't need.

## Conceptual design

The library can be thought of as a parser combinator library. It offers
a DSL (that consists of Python classes) to construct the parser for
received messages. Parser has a signature

```
parse(accum: Accumulator, data: bytes) -> Tuple[Accumulator, bytes]: ...
```

Accumulator can be any user-provided type, e.g. a dict or a data object.
Parser consumes some bytes from the supplied slice, updates the accumulator,
and returns a tuple of the modified accumulator and the remaining slice of
bytes that remained unparsed.

For a message with hierarchical structure (like most of netlink messages),
a parser can be constructed that knows which subtrees to descend into,
and which attribute values to collect in the accumulator. Other parts of
the message will be jumped over, saving resources. In addition, the
parser can raise an exception `StopParsing`, and then the result of
partial parse will not be included in the results.

Same classes that are used to define parsers can serve the second purpose
of constructing and serializing a message to be sent.

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

Documentation TBD. Refer to the code in the "examples" directory in the
meantime.
