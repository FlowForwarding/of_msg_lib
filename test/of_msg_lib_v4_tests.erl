%%------------------------------------------------------------------------------
%% Copyright 2013 FlowForwarding.org
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%%     http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing, software
%% distributed under the License is distributed on an "AS IS" BASIS,
%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%% See the License for the specific language governing permissions and
%% limitations under the License.
%%-----------------------------------------------------------------------------

%% @author Erlang Solutions Ltd. <openflow@erlang-solutions.com>
%% @copyright 2013 FlowForwarding.org
-module(of_msg_lib_v4_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("of_protocol/include/of_protocol.hrl").

-define(V4, 4).
-define(MAC_ADDR, <<1,2,3,4,5,6>>).

of_msg_lib_test_() ->
    [
     {"Get features", fun get_features/0},
     {"Get config", fun get_config/0},
     {"Set config", fun set_config/0},
     {"Send packet", fun send_packet/0},
     {"Flow add", fun flow_add/0},
     {"Flow modify", fun flow_modify/0},
     {"flow delete", fun flow_delete/0},
     {"group add", fun group_add/0},
     {"group modify", fun group_modify/0},
     {"group delete", fun group_delete/0},
     {"set port up", fun set_port_up/0},
     {"set port down", fun set_port_down/0},
     {"set port recv", fun set_port_recv/0},
     {"set port no recv", fun set_port_no_recv/0},
     {"set port fwd", fun set_port_fwd/0},
     {"set port no fwd", fun set_port_no_fwd/0},
     {"set port packet in", fun set_port_packet_in/0},
     {"set port no packet in", fun set_port_no_packet_in/0},
     {"get description", fun get_description/0},
     {"get flow statistsics", fun get_flow_statistsics/0},
     {"get aggregate statistics", fun get_aggregate_statistics/0},
     {"get table stats", fun get_table_stats/0},
     {"get table features", fun get_table_features/0},
     {"set table features", fun set_table_features/0},
     {"get port descriptions", fun get_port_descriptions/0},
     {"get port statistics", fun get_port_statistics/0},
     {"get queue statistics", fun get_queue_statistics/0},
     {"get group statistics", fun get_group_statistics/0},
     {"get group descriptions", fun get_group_descriptions/0},
     {"get group features", fun get_group_features/0},
     {"get meter stats", fun get_meter_stats/0},
     {"get meter configuration", fun get_meter_configuration/0},
     {"get meter features", fun get_meter_features/0},
     {"experimenter", fun experimenter/0},
     {"barrier", fun barrier/0},
     {"get queue configuration", fun get_queue_configuration/0},
     {"set role", fun set_role/0},
     {"get async configuration", fun get_async_configuration/0},
     {"set async configuration", fun set_async_configuration/0},
     {"meter add", fun meter_add/0},
     {"meter modify", fun meter_modify/0},
     {"meter delete", fun meter_delete/0}
    ].

get_features() ->
    Msg = of_msg_lib:get_features(?V4),
    ?assertEqual(Msg, encode_decode(?V4, Msg)).

get_config() ->
    Msg = of_msg_lib:get_config(?V4),
    ?assertEqual(Msg, encode_decode(?V4, Msg)).

set_config() ->
    SendMissLen = 256,
    Msg = of_msg_lib:set_config(?V4, [], SendMissLen),
    ?assertEqual(Msg, encode_decode(?V4, Msg)),

    Msg1 = of_msg_lib:set_config(?V4, [frag_drop], SendMissLen),
    ?assertEqual(Msg1, encode_decode(?V4, Msg1)).

send_packet() ->
    Actions = [{set_field, tcp_dst, <<80:16>>}],
    Msg = of_msg_lib:send_packet(?V4, 128, 3, Actions),
    ?assertEqual(Msg, encode_decode(?V4, Msg)),

    Msg1 = of_msg_lib:send_packet(?V4, <<1,2,3,4,5,6,7>>, 3, Actions),
    ?assertEqual(Msg1, encode_decode(?V4, Msg1)).

flow_add() ->
    Msg = of_msg_lib:flow_add(?V4,
                              [{in_port,6}, {eth_dst,<<0,0,0,0,0,8>>}],
                              [{write_actions,[{group,3}]}],
                              [{table_id,1}]),
    ?assertEqual(Msg, encode_decode(?V4, Msg)).

flow_modify() ->
    Msg = of_msg_lib:flow_modify(?V4,
                                 [{in_port,6}, {eth_dst,<<0,0,0,0,0,8>>}],
                                 [{write_actions,[{group,3}]}],
                                 [{table_id,4},
                                  {priority,6},
                                  {flags,[]}]),
    ?assertEqual(Msg, encode_decode(?V4, Msg)),

    Msg1 = of_msg_lib:flow_modify(?V4,
                                  [{in_port,6}, {eth_dst,<<0,0,0,0,0,8>>}],
                                  [{write_actions,[{group,3}]}],
                                  [strict,
                                   {table_id,4},
                                   {priority,6},
                                   {flags,[]}]),
    ?assertEqual(Msg1, encode_decode(?V4, Msg1)).

flow_delete() ->
    Msg = of_msg_lib:flow_delete(?V4,
                                 [{in_port,6}, {eth_dst,<<0,0,0,0,0,8>>}],
                                 [{table_id,4},
                                  {priority,6},
                                  {flags,[]},
                                  {out_port,2}]),
    ?assertEqual(Msg, encode_decode(?V4, Msg)),

    Msg1 = of_msg_lib:flow_delete(?V4,
                                  [{in_port,6}, {eth_dst,<<0,0,0,0,0,8>>}],
                                  [strict,
                                   {table_id,4},
                                   {priority,6},
                                   {flags,[]}]),
    ?assertEqual(Msg1, encode_decode(?V4, Msg1)).

group_add() ->
    Msg = of_msg_lib:group_add(?V4, all, 5,
                               [{3,    %% weight
                                 7,    %% port_no
                                 5,    %% group_id
                                 [{set_field, tcp_dst, <<80:16>>}]  %% actions
                                }]),
    ?assertEqual(Msg, encode_decode(?V4, Msg)).

group_modify() ->
    Msg = of_msg_lib:group_modify(?V4, all, 5,
                                  [{3,    %% weight
                                    7,    %% port_no
                                    5,    %% group_id
                                    [{set_field, tcp_dst, <<80:16>>}]  %% actions
                                   }]),
    ?assertEqual(Msg, encode_decode(?V4, Msg)).

group_delete() ->
    Msg = of_msg_lib:group_delete(?V4, all, 5),
    ?assertEqual(Msg, encode_decode(?V4, Msg)).

set_port_up() ->
    Msg = of_msg_lib:set_port_up(?V4, ?MAC_ADDR, 5),
    ?assertEqual(Msg, encode_decode(?V4, Msg)).

set_port_down() ->
    Msg = of_msg_lib:set_port_down(?V4, ?MAC_ADDR, 5),
    ?assertEqual(Msg, encode_decode(?V4, Msg)).

set_port_recv() ->
    Msg = of_msg_lib:set_port_recv(?V4, ?MAC_ADDR, 5),
    ?assertEqual(Msg, encode_decode(?V4, Msg)).

set_port_no_recv() ->
    Msg = of_msg_lib:set_port_no_recv(?V4, ?MAC_ADDR, 5),
    ?assertEqual(Msg, encode_decode(?V4, Msg)).

set_port_fwd() ->
    Msg = of_msg_lib:set_port_fwd(?V4, ?MAC_ADDR, 5),
    ?assertEqual(Msg, encode_decode(?V4, Msg)).

set_port_no_fwd() ->
    Msg = of_msg_lib:set_port_no_fwd(?V4, ?MAC_ADDR, 5),
    ?assertEqual(Msg, encode_decode(?V4, Msg)).

set_port_packet_in() ->
    Msg = of_msg_lib:set_port_packet_in(?V4, ?MAC_ADDR, 5),
    ?assertEqual(Msg, encode_decode(?V4, Msg)).

set_port_no_packet_in() ->
    Msg = of_msg_lib:set_port_no_packet_in(?V4, ?MAC_ADDR, 5),
    ?assertEqual(Msg, encode_decode(?V4, Msg)).

get_description() ->
    Msg = of_msg_lib:get_description(?V4),
    ?assertEqual(Msg, encode_decode(?V4, Msg)).

get_flow_statistsics() ->
    Msg = of_msg_lib:get_flow_statistsics(?V4,
                                          3, %% table_id
                                          [{in_port,6}, {eth_dst,<<0,0,0,0,0,8>>}],
                                          []),
    ?assertEqual(Msg, encode_decode(?V4, Msg)).

get_aggregate_statistics() ->
    Msg = of_msg_lib:get_aggregate_statistics(?V4,
                                              3, %% table_id
                                              [{in_port,6},
                                               {eth_dst,<<0,0,0,0,0,8>>}],
                                              []),
    ?assertEqual(Msg, encode_decode(?V4, Msg)).

get_table_stats() ->
    Msg = of_msg_lib:get_table_stats(?V4),
    ?assertEqual(Msg, encode_decode(?V4, Msg)).

get_table_features() ->
    Msg = of_msg_lib:get_table_features(?V4),
    ?assertEqual(Msg, encode_decode(?V4, Msg)).

set_table_features() ->
    Features = [],   %% TODO Add features
    Msg = of_msg_lib:set_table_features(?V4, Features),
    ?assertEqual(Msg, encode_decode(?V4, Msg)).

get_port_descriptions() ->
    Msg = of_msg_lib:get_port_descriptions(?V4),
    ?assertEqual(Msg, encode_decode(?V4, Msg)).

get_port_statistics() ->
    Msg = of_msg_lib:get_port_statistics(?V4, 5),
    ?assertEqual(Msg, encode_decode(?V4, Msg)).

get_queue_statistics() ->
    Msg = of_msg_lib:get_queue_statistics(?V4,
                                          5,  %% PortNo
                                          3   %% QueueId
                                         ),
    ?assertEqual(Msg, encode_decode(?V4, Msg)).

get_group_statistics() ->
    Msg = of_msg_lib:get_group_statistics(?V4, 5),
    ?assertEqual(Msg, encode_decode(?V4, Msg)).

get_group_descriptions() ->
    Msg = of_msg_lib:get_group_descriptions(?V4),
    ?assertEqual(Msg, encode_decode(?V4, Msg)).

get_group_features() ->
    Msg = of_msg_lib:get_group_features(?V4),
    ?assertEqual(Msg, encode_decode(?V4, Msg)).

get_meter_stats() ->
    Msg = of_msg_lib:get_meter_stats(?V4, 4),
    ?assertEqual(Msg, encode_decode(?V4, Msg)).

get_meter_configuration() ->
    Msg = of_msg_lib:get_meter_configuration(?V4, 4),
    ?assertEqual(Msg, encode_decode(?V4, Msg)).

get_meter_features() ->
    Msg = of_msg_lib:get_meter_features(?V4),
    ?assertEqual(Msg, encode_decode(?V4, Msg)).

experimenter() ->
    Msg = of_msg_lib:experimenter(?V4,
                                  345,   %% Id
                                  33,    %% Type
                                  <<4,5,6,7,8,9>>  %% Data
                                 ),
    ?assertEqual(Msg, encode_decode(?V4, Msg)).

barrier() ->
    Msg = of_msg_lib:barrier(?V4),
    ?assertEqual(Msg, encode_decode(?V4, Msg)).

get_queue_configuration() ->
    Msg = of_msg_lib:get_queue_configuration(?V4, 76),
    ?assertEqual(Msg, encode_decode(?V4, Msg)).

set_role() ->
    Msg = of_msg_lib:set_role(?V4, slave, 34),
    ?assertEqual(Msg, encode_decode(?V4, Msg)).

get_async_configuration() ->
    Msg = of_msg_lib:get_async_configuration(?V4),
    ?assertEqual(Msg, encode_decode(?V4, Msg)).

set_async_configuration() ->
    PacketInMask = {[],[]},
    PortStatusMask = {[],[]},
    FlowRemovedMask = {[],[]},
    Msg = of_msg_lib:set_async_configuration(?V4,
                                             PacketInMask,
                                             PortStatusMask,
                                             FlowRemovedMask),
    ?assertEqual(Msg, encode_decode(?V4, Msg)).

meter_add() ->
    Flags = [],
    MeterId = 10,
    Bands = [],
    Msg = of_msg_lib:meter_add(?V4, Flags, MeterId, Bands),
    ?assertEqual(Msg, encode_decode(?V4, Msg)).

meter_modify() ->
    Flags = [],
    MeterId = 10,
    Bands = [],
    Msg = of_msg_lib:meter_modify(?V4, Flags, MeterId, Bands),
    ?assertEqual(Msg, encode_decode(?V4, Msg)).

meter_delete() ->
    Msg = of_msg_lib:meter_delete(?V4, 10),
    ?assertEqual(Msg, encode_decode(?V4, Msg)).


%%% ==================================================================

encode_decode(?V4, Msg) ->
    Bin = ofp_v4_encode:do(#ofp_message{ version = ?V4, xid = 1, body = Msg }),
    {ok, #ofp_message{ version = ?V4, xid = 1, body = Msg1 }, <<>>} = ofp_v4_decode:do(Bin),
    Msg1.
