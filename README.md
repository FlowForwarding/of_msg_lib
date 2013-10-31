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
1> of_msg_lib:flow_modify(4,
                          [{in_port,6}, {eth_dst,<<0,0,0,0,0,8>>}],
                          [{write_actions,[{group,3}]}],
                          [{table_id,4},
                           {priority,6},
                           {flags,[]}]).
{ofp_message,4,undefined,0,
    #ofp_flow_mod{
        cookie = <<0,0,0,0,0,0,0,0>>,
        cookie_mask = <<0,0,0,0,0,0,0,0>>,
        table_id = 4,command = modify,idle_timeout = 0,
        hard_timeout = 0,priority = 6,buffer_id = no_buffer,
        out_port = any,out_group = any,flags = [],
        match =
            #ofp_match{
                fields =
                    [#ofp_field{
                         class = openflow_basic,name = in_port,has_mask = false,
                         value = <<0,0,0,...>>,
                         mask = undefined},
                     #ofp_field{
                         class = openflow_basic,name = eth_dst,has_mask = false,
                         value = <<0,0,...>>,
                         mask = undefined}]},
        instructions =
            [#ofp_instruction_write_actions{
                 seq = 4,
                 actions = [#ofp_action_group{seq = 15,group_id = 3}]}]}}
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

```
1> Msg = #ofp_message{
             version = 4,type = undefined,xid = 2,
             body =
                 #ofp_flow_removed{
                     cookie = <<1,2,3,4,5,6>>,
                     priority = 2,reason = delete,table_id = 3,duration_sec = 23,
		     duration_nsec = 456,idle_timeout = 333,hard_timeout = 444,
            	     packet_count = 45567,byte_count = 3456,
            	     match =
                         #ofp_match{
                    	     fields =
                                 [#ofp_field{
                             	      class = openflow_basic,
				      name = in_port,
				      has_mask = false,
                             	      value = 6,mask = undefined},
                         	 #ofp_field{
                                     class = openflow_basic,
				     name = eth_dst,
				     has_mask = false,
                             	     value = <<0,0,0,0,0,8>>,
                             	     mask = undefined}]}}}.

2>  of_msg_lib:decode(Msg).
{flow_removed,2,
              [{cookie,<<1,2,3,4,5,6>>},
               {priority,2},
               {reason,delete},
               {table_id,3},
               {duration_sec,23},
               {duration_nsec,456},
               {idle_timeout,333},
               {hard_timeout,444},
               {packet_count,45567},
               {byte_count,3456},
               {match,[{in_port,6},{eth_dst,<<0,0,0,0,0,8>>}]}]}
```