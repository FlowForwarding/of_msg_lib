of_msg_lib
==========

The OpenFlow Message Library aims to provide a simpler interface for application programmers when interacting with OpenFlow switches via the of_protocol library. Functions are named after what logical operation is performed on the switch rather that what the underlaying OpenFlow messages that are used to perform it. All functions that create messages take property lists as arguments instead of the records defined in of_protocol.

Building
========

To build of_msg_lib

Get all dependencies

```
rebar get-deps
```

Compile

```
rebar compile
```

To run the unit tests

```
rebar skip_deps=true eunit
```