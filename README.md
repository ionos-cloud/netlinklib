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

The same classes that are used to define parsers can serve the second purpose
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

Unfortunately, kernel code usually does not contain information about the
_type_ of NLA values of netlink messages. Dealing with the interpretation
of the byte values of NLAs has to be left to user of the library.

## High Level API

Final form of functions handling dumps, transactions and event handling are
still TBD. Refer to the code in the "examples" directory in the meantime.

When a dump operation is requested, and the kernel returns `NLM_F_DUMP_INTR`
in one of the response messages, the fact is exposed as `NllDumpInterrupted`
exception, that should be interpreted as an advise to repeat the operation.

The user of the library needs to provide the structure of the netlink
message to construct or to parse by using a DSL made of Python classes.

## DSL Types

### NllHdr

This is the base datatype used for the automatic class generation in `mknetlinkdefs` and is a subclass of `dict`. Subclasses have `SIZE` attribute used during parsing as well as `PACKFMT` in `struct` format used in both parsing and serialization procedures.

This class serves as a parent for generated subclasses, and is not used
directly. Only generated subclasses should be used.

Instances may be passed either values of type `T` (for serializing) or callbacks of type
```
callback(accum: Accumulator, val: T) -> Accumulator
```
for parsing. These functions are called when an element is encountered in the message that is being parsed, and can update the accumulator, raise StopParsing to end parsing of current message, or have any other functionality needed by the user.

`Accumulator` can be any object type provided by the user, that is suitable for storing parsed data, for example a simple `dict`, or a data object.

An instance initialized with callbacks can only be used for parsing (not for serialization), and conversely, instance initialized with values can only be used for serialization.

### NllMsg

Object consisting of an `NllHdr` (header) and an optional sequence of `NllMsg` children (payload). Child messages are all expected to have the same header type. This is the main abstraction used by this library and every netlink msg tree and subtree can be expressed as an `NllMsg`.

Exposes two main functions:

```
parse(accum: Accumulator, data: bytes) -> Tuple[Accumulator, bytes]: ...
```

and

```
__bytes__(self) -> bytes:
```

#### parse
From raw slice, first parse the header. For each field in the header, any user defined callbacks are run.

User is allowed to specify "size" field in `NllMsg` instantiation. If such a field exists, this field is extracted from the header and used to determine how much of the slice is to be consumed. If no size field exists but `NllMsg` instance does not contain a child `NllMsg` sequence, the header size is used. Otherwise the entirety of the remaining data is consumed.

The remaining data from the end of the header till the end of the message is used for "payload" parsing. This occurs in a dispatched manner. Child `NllMsg`s each have an optional `tag` value defined. If user provides "tag field" argument in parent `NllMsg` construction, the value in this field is extracted during header parsing and used to select the correct "child" parser by matching the value with child's `tag`. This process can be repeated until payload data is exhausted. If no matching child is found, record is skipped.

If no "tag field" is defined by the parent, then the parent should have maximum one child object which is solely used to consume the payload.


#### __bytes__
Returns byte representation of `NllMsg` as packed header (using PACKFMT) followed by the byte representations of all child `NllMsg`s.

e.g. `bytes(ifinfomsg())`

### NllAttr
`NllMsg` using `rtattr` as header. User provides attribute type integer, library handles correct construction of `rtattr` header, size and tag fields, etc.

### NlaUnion
Special NllAttr subtype. Used to handle parsing situations where contents of one attribute depends on the contents of a sibling attribute. e.g. interpretation of `IFLA_INFO_DATA` contents depends on the value of `IFLA_INFO_KIND`.

Takes `resolve: Callable[[Accumulator], NllMsg]` argument during instation. This function is called during parsing to substitute the union type with the proper `NllMsg` depending on the contents of the accumulator.

This mechanism only works when the "defining" element comes before the "dependent" element in the parsed byte stream. In practice, messages returned by the kernel satisfy this condition.

### Scalar Attributes (Nla\_\_\_)
Special versions of NllAttr. Instead of sequence of `NllMsg` as payload, these parse/encode single scalar values (integers, strings, IP addresses, etc.). See `core.py` for full list of scalar types.

Each take during construction either a value (for encoding) or a callback (for parsing), similar to `NllHdr`.
