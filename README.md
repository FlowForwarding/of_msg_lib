of_msg_lib
==========

The OpenFlow Message Library aims to provide a simpler interface for application programmers when interacting with OpenFlow switches via the [of_protocol](https://github.com/FlowForwarding/of_protocol) library. Functions are named after what logical operation is performed on the switch rather that what the underlaying OpenFlow messages that are used to perform it. All functions that create messages take property lists as arguments instead of the records defined in of_protocol.

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

Using
=====

Requests
--------

All functions that create request messages take protocol version and request specific parameters and return an of_message record that can be encoded using of_protocol.

### Matches

Packet header field matches are specified as a list of field matches, where each field match is a tuple ```{Name, Value}``` or ```{Name, Value, Mask}```.

### Instructions

Instructions are also gives as a list of instructions, where each instruction is a tuple.
### Example

To create a request to add a flow

```
Msg = of_msg_lib:flow_modify(?V4,
                             [{in_port,6}, {eth_dst,<<0,0,0,0,0,8>>}],
                             [{write_actions,[{group,3}]}],
                             [{table_id,4},
                              {priority,6},
                              {flags,[]}]).
```

Responses and Events
--------------------

Response messages and asynchronous event messages must first be decoded using of_protocol to get a of_message record. This can then be further decoded by

```
of_msg_lib:decode(Rec)
```

to get a tuple with

```
{MsgName, Xid, Params}
```

### Example

