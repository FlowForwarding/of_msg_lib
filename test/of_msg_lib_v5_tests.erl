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
-module(of_msg_lib_v5_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("of_protocol/include/of_protocol.hrl").
-include_lib("of_protocol/include/ofp_v5.hrl").

-define(V5, 5).
-define(MAC_ADDR, <<1,2,3,4,5,6>>).

of_msg_lib_test_() ->
    [
     {"Create error v5", fun create_error_v5/0},
     {"Hello", fun out_hello/0},
     {"Echo request", fun echo_request/0},
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
     {"get flow statistics", fun get_flow_statistics/0},
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
     {"experimenter", fun experimenter/0}, %% CHANGE 
     {"barrier", fun barrier/0},
     {"get queue configuration", fun get_queue_configuration/0},
     {"set role", fun set_role/0},
     {"get async configuration", fun get_async_configuration/0},
     {"set async configuration", fun set_async_configuration/0},
     {"meter add", fun meter_add/0},
     {"meter modify", fun meter_modify/0},
     {"meter delete", fun meter_delete/0},
     {"flow_monitor_request_add", fun flow_monitor_request_add/0 },
     {"flow_monitor_request_delete", fun flow_monitor_request_delete/0 },
     {"flow_monitor_request_modify", fun flow_monitor_request_modify/0 },
     {"get_table_desc", fun get_table_desc/0 },
     {"get_queue_desc", fun get_queue_desc/0 },
     {"set_table_mod_eviction", fun set_table_mod_eviction/0 },
     {"set_table_mod_vacancy_events", fun set_table_mod_vacancy_events/0 },
     {"requestforward", fun requestforward/0 },
     {"bundle_ctrl_msg", fun bundle_ctrl_msg/0 },
     {"bundle_add_msg", fun bundle_add_ms/0 }
    ].

decode_test_() ->
    [
     {"hello v5", fun in_hello_v5/0},
     {"hello v3-", fun in_hello_v3minus/0},
     {"hello v15", fun in_hello_v15/0},
     {"Features reply", fun dec_features_reply/0},
     {"Config reply", fun dec_config_reply/0},
     {"Desc reply", fun dec_desc_reply/0},
     {"Aggregate stats reply", fun dec_aggregate_stats_reply/0},
     {"Group features reply", fun dec_group_features_reply/0},
     {"Meter features reply", fun dec_meter_features_reply/0},
     {"Experimenter reply", fun dec_experimenter_reply/0},
     {"Queue get config reply", fun dec_queue_get_config_reply/0},
     {"Barrier reply", fun dec_barrier_reply/0},
     {"Role reply", fun dec_role_reply/0},
     {"Get async reply", fun dec_get_async_reply/0},
     {"Flow stats reply", fun dec_flow_stats_reply/0},
     {"Table stats reply", fun dec_table_stats_reply/0},
     {"Table features reply", fun dec_table_features_reply/0},
     {"Port stats reply", fun dec_port_stats_reply/0},
     {"Port desc reply", fun dec_port_desc_reply/0},
     {"Queue stats reply", fun dec_queue_stats_reply/0},
     {"Group stats reply", fun dec_group_stats_reply/0},
     {"Group desc reply", fun dec_group_desc_reply/0},
     {"Meter stats reply", fun dec_meter_stats_reply/0},
     {"Meter config reply", fun dec_meter_config_reply/0},
     {"packet_in", fun dec_packet_in/0},
     {"flow_removed", fun dec_flow_removed/0},
     {"Port status", fun dec_port_status/0},
     {"Error msg", fun dec_error_msg/0},
     {"Error msg experimenter", fun dec_error_msg_experimenter/0},
     {"Echo request", fun dec_echo_request/0},
     {"Echo reply", fun dec_echo_reply/0},
     {"Experimenter", fun dec_experimenter/0}
    ].

%%% ==================================================================
%% MSG LIB TESTS:

create_error_v5() ->
    Msg = of_msg_lib:create_error(5, hello_failed, compatible),
    ?debugMsg(io_lib:format("~n~P~n", [Msg, -1])).

out_hello() ->
    % version bit field is returned in reverse sorted order, so keep
    % them that way in the sample data so the assertEqual is true.
    Msg = of_msg_lib:hello(?V5, [5,4]),
    ?assertEqual(Msg, encode_decode(?V5, Msg)).

echo_request() ->
    Msg = of_msg_lib:echo_request(?V5, <<1,2,3,4,5,6,7>>),
    ?assertEqual(Msg, encode_decode(?V5, Msg)).

get_features() ->
    Msg = of_msg_lib:get_features(?V5),
    ?assertEqual(Msg, encode_decode(?V5, Msg)).

get_config() ->
    Msg = of_msg_lib:get_config(?V5),
    ?assertEqual(Msg, encode_decode(?V5, Msg)).

set_config() ->
    SendMissLen = 256,
    Msg = of_msg_lib:set_config(?V5, [], SendMissLen),
    ?assertEqual(Msg, encode_decode(?V5, Msg)),

    Msg1 = of_msg_lib:set_config(?V5, [frag_drop], SendMissLen),
    ?assertEqual(Msg1, encode_decode(?V5, Msg1)).

send_packet() ->
    Actions = [{set_field, tcp_dst, <<80:16>>}],
    Msg = of_msg_lib:send_packet(?V5, 128, 3, Actions),
    ?assertEqual(Msg, encode_decode(?V5, Msg)),

    Msg1 = of_msg_lib:send_packet(?V5, <<1,2,3,4,5,6,7>>, 3, Actions),
    ?assertEqual(Msg1, encode_decode(?V5, Msg1)).

flow_add() ->
    Msg = of_msg_lib:flow_add(?V5,
                              [{in_port,6}, {eth_dst,<<0,0,0,0,0,8>>}],
                              [{write_actions,[{group,3}]}],
                              [{table_id,1}]),
    ?assertEqual(Msg, encode_decode(?V5, Msg)).

flow_modify() ->
    Msg = of_msg_lib:flow_modify(?V5,
                                 [{in_port,6}, {eth_dst,<<0,0,0,0,0,8>>}],
                                 [{write_actions,[{group,3}]}],
                                 [{table_id,4},
                                  {priority,6},
                                  {flags,[]}]),
    ?assertEqual(Msg, encode_decode(?V5, Msg)),

    Msg1 = of_msg_lib:flow_modify(?V5,
                                  [{in_port,6}, {eth_dst,<<0,0,0,0,0,8>>}],
                                  [{write_actions,[{group,3}]}],
                                  [strict,
                                   {table_id,4},
                                   {priority,6},
                                   {flags,[]}]),
    ?assertEqual(Msg1, encode_decode(?V5, Msg1)).

flow_delete() ->
    Msg = of_msg_lib:flow_delete(?V5,
                                 [{in_port,6}, {eth_dst,<<0,0,0,0,0,8>>}],
                                 [{table_id,4},
                                  {priority,6},
                                  {flags,[]},
                                  {out_port,2}]),
    ?assertEqual(Msg, encode_decode(?V5, Msg)),

    Msg1 = of_msg_lib:flow_delete(?V5,
                                  [{in_port,6}, {eth_dst,<<0,0,0,0,0,8>>}],
                                  [strict,
                                   {table_id,4},
                                   {priority,6},
                                   {flags,[]}]),
    ?assertEqual(Msg1, encode_decode(?V5, Msg1)).

group_add() ->
    Msg = of_msg_lib:group_add(?V5, all, 5,
                               [{3,    %% weight
                                 7,    %% port_no
                                 5,    %% group_id
                                 [{set_field, tcp_dst, <<80:16>>}]  %% actions
                                }]),
    ?assertEqual(Msg, encode_decode(?V5, Msg)).

group_modify() ->
    Msg = of_msg_lib:group_modify(?V5, all, 5,
                                  [{3,    %% weight
                                    7,    %% port_no
                                    5,    %% group_id
                                    [{set_field, tcp_dst, <<80:16>>}]  %% actions
                                   }]),
    ?assertEqual(Msg, encode_decode(?V5, Msg)).

group_delete() ->
    Msg = of_msg_lib:group_delete(?V5, all, 5),
    ?assertEqual(Msg, encode_decode(?V5, Msg)).

set_port_up() ->
    PortProperties = [],
    Msg = of_msg_lib:set_port_up(?V5, ?MAC_ADDR, 5, PortProperties),
    ?assertEqual(Msg, encode_decode(?V5, Msg)).

set_port_down() ->
    PortProperties = [],
    Msg = of_msg_lib:set_port_down(?V5, ?MAC_ADDR, 5, PortProperties),
    ?assertEqual(Msg, encode_decode(?V5, Msg)).

set_port_recv() ->
    PortProperties = [],
    Msg = of_msg_lib:set_port_recv(?V5, ?MAC_ADDR, 5, PortProperties),
    ?assertEqual(Msg, encode_decode(?V5, Msg)).

set_port_no_recv() ->
    PortProperties = [],
    Msg = of_msg_lib:set_port_no_recv(?V5, ?MAC_ADDR, 5, PortProperties),
    ?assertEqual(Msg, encode_decode(?V5, Msg)).

set_port_fwd() ->
    PortProperties = [],
    Msg = of_msg_lib:set_port_fwd(?V5, ?MAC_ADDR, 5, PortProperties),
    ?assertEqual(Msg, encode_decode(?V5, Msg)).

set_port_no_fwd() ->
    PortProperties = [],
    Msg = of_msg_lib:set_port_no_fwd(?V5, ?MAC_ADDR, 5, PortProperties),
    ?assertEqual(Msg, encode_decode(?V5, Msg)).

set_port_packet_in() ->
    PortProperties = [],
    Msg = of_msg_lib:set_port_packet_in(?V5, ?MAC_ADDR, 5, PortProperties),
    ?assertEqual(Msg, encode_decode(?V5, Msg)).

set_port_no_packet_in() ->
    PortProperties = [],
    Msg = of_msg_lib:set_port_no_packet_in(?V5, ?MAC_ADDR, 5, PortProperties),
    ?assertEqual(Msg, encode_decode(?V5, Msg)).

get_description() ->
    Msg = of_msg_lib:get_description(?V5),
    ?assertEqual(Msg, encode_decode(?V5, Msg)).

get_flow_statistics() ->
    Msg = of_msg_lib:get_flow_statistics(?V5,
                                          3, %% table_id
                                          [{in_port,6}, {eth_dst,<<0,0,0,0,0,8>>}],
                                          []),
    ?assertEqual(Msg, encode_decode(?V5, Msg)).

get_aggregate_statistics() ->
    Msg = of_msg_lib:get_aggregate_statistics(?V5,
                                              3, %% table_id
                                              [{in_port,6},
                                               {eth_dst,<<0,0,0,0,0,8>>}],
                                              []),
    ?assertEqual(Msg, encode_decode(?V5, Msg)).

get_table_stats() ->
    Msg = of_msg_lib:get_table_stats(?V5),
    ?assertEqual(Msg, encode_decode(?V5, Msg)).

get_table_features() ->
    Msg = of_msg_lib:get_table_features(?V5),
    ?assertEqual(Msg, encode_decode(?V5, Msg)).

set_table_features() ->
    Features = [],   %% TODO Add features
    Msg = of_msg_lib:set_table_features(?V5, Features),
    ?assertEqual(Msg, encode_decode(?V5, Msg)).

get_port_descriptions() ->
    Msg = of_msg_lib:get_port_descriptions(?V5),
    ?assertEqual(Msg, encode_decode(?V5, Msg)).

get_port_statistics() ->
    Msg = of_msg_lib:get_port_statistics(?V5, 5),
    ?assertEqual(Msg, encode_decode(?V5, Msg)).

get_queue_statistics() ->
    Msg = of_msg_lib:get_queue_statistics(?V5,
                                          5,  %% PortNo
                                          3   %% QueueId
                                         ),
    ?assertEqual(Msg, encode_decode(?V5, Msg)).

get_group_statistics() ->
    Msg = of_msg_lib:get_group_statistics(?V5, 5),
    ?assertEqual(Msg, encode_decode(?V5, Msg)).

get_group_descriptions() ->
    Msg = of_msg_lib:get_group_descriptions(?V5),
    ?assertEqual(Msg, encode_decode(?V5, Msg)).

get_group_features() ->
    Msg = of_msg_lib:get_group_features(?V5),
    ?assertEqual(Msg, encode_decode(?V5, Msg)).

get_meter_stats() ->
    Flags = [], %% TODO: add actual flags...
    Msg = of_msg_lib:get_meter_stats(?V5, 4, Flags),
    ?assertEqual(Msg, encode_decode(?V5, Msg)).

get_meter_configuration() ->
    Flags = [], %% TODO: add actual flags...
    Msg = of_msg_lib:get_meter_configuration(?V5, 4, Flags),
    ?assertEqual(Msg, encode_decode(?V5, Msg)).

get_meter_features() ->
    Flags = [], %% TODO: add actual flags...    
    Msg = of_msg_lib:get_meter_features(?V5,Flags),
    ?assertEqual(Msg, encode_decode(?V5, Msg)).

experimenter() ->
    Msg = of_msg_lib:experimenter(?V5,
                                  345,   %% Id
                                  33,    %% Type
                                  <<4,5,6,7,8,9>>  %% Data
                                 ),
    ?assertEqual(Msg, encode_decode(?V5, Msg)).

barrier() ->
    Msg = of_msg_lib:barrier(?V5),
    ?assertEqual(Msg, encode_decode(?V5, Msg)).

get_queue_configuration() ->
    Msg = of_msg_lib:get_queue_configuration(?V5, 76),
    ?assertEqual(Msg, encode_decode(?V5, Msg)).

set_role() ->
    Msg = of_msg_lib:set_role(?V5, slave, 34),
    ?assertEqual(Msg, encode_decode(?V5, Msg)).

get_async_configuration() ->
    Msg = of_msg_lib:get_async_configuration(?V5),
    ?assertEqual(Msg, encode_decode(?V5, Msg)).

set_async_configuration() ->
    PacketInMask = {[],[]},
    PortStatusMask = {[],[]},
    FlowRemovedMask = {[],[]},
    Msg = of_msg_lib:set_async_configuration(?V5,
                                             PacketInMask,
                                             PortStatusMask,
                                             FlowRemovedMask),
    ?assertEqual(Msg, encode_decode(?V5, Msg)).

meter_add() ->
    Flags = [],
    MeterId = 10,
    Bands = [],
    Msg = of_msg_lib:meter_add(?V5, Flags, MeterId, Bands),
    ?assertEqual(Msg, encode_decode(?V5, Msg)).

meter_modify() ->
    Flags = [],
    MeterId = 10,
    Bands = [],
    Msg = of_msg_lib:meter_modify(?V5, Flags, MeterId, Bands),
    ?assertEqual(Msg, encode_decode(?V5, Msg)).

meter_delete() ->
    Msg = of_msg_lib:meter_delete(?V5, 10),
    ?assertEqual(Msg, encode_decode(?V5, Msg)).

flow_monitor_request_add() ->
    Flags = [],
    Matches = [{in_port,6},
               {eth_dst,<<0,0,0,0,0,8>>} ],
    MonitorId = 1,
    Opts = [{out_port,12345},
            {out_group,1},
            {monitor_flags,[]},
            {table_id,1}
           ],
    Msg = of_msg_lib:flow_monitor_request_add(?V5, Flags, Matches, MonitorId, Opts),
    ?assertEqual(Msg, encode_decode(?V5, Msg)).

flow_monitor_request_delete() ->
    Flags = [],
    Matches = [{in_port,6},
               {eth_dst,<<0,0,0,0,0,8>>} ],
    MonitorId = 1,
    Opts = [{out_port,12345},
            {out_group,1},
            {monitor_flags,[]},
            {table_id,1}
           ],
    Msg = of_msg_lib:flow_monitor_request_delete(?V5, Flags, Matches, MonitorId, Opts),
    ?assertEqual(Msg, encode_decode(?V5, Msg)).

flow_monitor_request_modify() ->
    Flags = [],
    Matches = [{in_port,6},
               {eth_dst,<<0,0,0,0,0,8>>} ],
    MonitorId = 1,
    Opts = [{out_port,12345},
            {out_group,1},
            {monitor_flags,[]},
            {table_id,1}
           ],
    Msg = of_msg_lib:flow_monitor_request_modify(?V5, Flags, Matches, MonitorId, Opts),
    ?assertEqual(Msg, encode_decode(?V5, Msg)).

get_table_desc() ->
    Flags = [],
    Msg = of_msg_lib:get_table_desc(?V5, Flags),
    ?assertEqual(Msg, encode_decode(?V5, Msg)).

get_queue_desc() ->
    Flags = [],
    PortNo = 12345,
    QueueId = 1,
    Msg = of_msg_lib:get_queue_desc(?V5, Flags, PortNo, QueueId),
    ?assertEqual(Msg, encode_decode(?V5, Msg)).

set_table_mod_eviction() ->
    Properties = [{table_mod_prop_eviction,[other]}],
    Opts = [{table_id,1}],
    Msg = of_msg_lib:set_table_mod_eviction(?V5, Properties, Opts),
    ?assertEqual(Msg, encode_decode(?V5, Msg)).

set_table_mod_vacancy_events() ->
    Properties = [{table_mod_prop_eviction,[other]}],
    Opts = [{table_id,1}],
    Msg = of_msg_lib:set_table_mod_vacancy_events(?V5, Properties, Opts),
    ?assertEqual(Msg, encode_decode(?V5, Msg)).

%% TODO
requestforward() ->
    M = of_msg_lib:echo_request(?V5, <<1,2,3,4,5,6,7,8>>),
    Msg = of_msg_lib:requestforward(?V5, M),
    ?assertEqual(Msg, encode_decode_rf(?V5, Msg)).

%% TODO
bundle_ctrl_msg() ->
    BundleId = 1,
    CtrlType = open_request,
    Flag = [atomic,ordered],
    Properties = [{bundle_prop_experimenter,1,1,<<1,2,3,4,5,6,7,8>>}],
    Msg = of_msg_lib:bundle_ctrl_msg(?V5, BundleId, CtrlType, Flag, Properties),
    ?assertEqual(Msg, encode_decode(?V5, Msg)).

%% TODO
bundle_add_ms() ->
    BundleId = 1,
    Flag = [atomic,ordered],
    BundleMsg = of_msg_lib:echo_request(?V5, <<1,2,3,4,5,6,7,8>>),
    Properties = [{bundle_prop_experimenter,1,1,<<1,2,3,4,5,6,7,8>>}],
    Msg = of_msg_lib:bundle_add_msg(?V5, BundleId, Flag, BundleMsg, Properties),
    ?assertEqual(Msg, encode_decode_ba(?V5, Msg)).

%%% ==================================================================
%% DECODE TESTS :
%%% ==================================================================

in_hello_v5() ->
    Body = #ofp_hello{elements = [{versionbitmap, [5,4]}]},
    Msg = #ofp_message{version = ?V5, xid = 0, body = Body},
    Expect = {hello, 0, [{versionbitmap, [5,4]}]},
    Res = of_msg_lib:decode(Msg),
    ?assertEqual(Expect, Res).

in_hello_v3minus() ->
    Body = #ofp_hello{},
    Msg = #ofp_message{version = 3, xid = 0, body = Body},
    Expect = {hello, 0, []},
    Res = of_msg_lib:decode(Msg),
    ?assertEqual(Expect, Res).

in_hello_v15() ->
    Body = #ofp_hello{elements = [{versionbitmap, [15]}]},
    Msg = #ofp_message{version = 15, xid = 0, body = Body},
    Expect = {hello, 0, [{versionbitmap, [15]}]},
    Res = of_msg_lib:decode(Msg),
    ?assertEqual(Expect, Res).

dec_features_reply() ->
    Body = #ofp_features_reply{
             datapath_mac = ?MAC_ADDR,
             datapath_id = 100,
             n_buffers = 1024,
             n_tables = 128,
             auxiliary_id = 1,
             capabilities = [flow_stats,
                             table_stats,
                             port_stats,
                             group_stats,
                             ip_reasm,
                             queue_stats,
                             port_blocked]
            },
    Expect = {features_reply, 2,
              [{datapath_mac,<<1,2,3,4,5,6>>},
               {datapath_id,100},
               {n_buffers,1024},
               {n_tables,128},
               {auxiliary_id,1},
               {capabilities,[flow_stats,
                              table_stats,
                              port_stats,
                              group_stats,
                              ip_reasm,
                              queue_stats,
                              port_blocked]}]},
    Msg = #ofp_message{version = ?V5, xid=2, body = Body},
    Res = of_msg_lib:decode(Msg),
    ?assertEqual(Expect, Res).

dec_config_reply() ->
    Body = #ofp_get_config_reply{
              flags = [],
              miss_send_len = 128
             },
    Expect = {config_reply, 2,
              [{flags, []},
               {miss_send_len, 128}]},
    Msg = #ofp_message{version = ?V5, xid=2, body = Body},
    Res = of_msg_lib:decode(Msg),
    ?assertEqual(Expect, Res).

dec_desc_reply() ->
    Flags = [],
    Mfr_desc = <<"Manufacturer Name">>,
    Hw_desc = <<"Switch Name">>,
    Sw_desc = <<"Software Version">>,
    Serial_num = <<"Serial Num">>,
    Dp_desc = <<"DP Desc">>,
    Body = #ofp_desc_reply{
              flags = Flags,
              mfr_desc = Mfr_desc,
              hw_desc = Hw_desc,
              sw_desc = Sw_desc,
              serial_num = Serial_num,
              dp_desc = Dp_desc
             },
    Expect = {desc_reply, 2, [{flags, Flags},
                              {mfr_desc, Mfr_desc},
                              {hw_desc, Hw_desc},
                              {sw_desc, Sw_desc},
                              {serial_num, Serial_num},
                              {dp_desc, Dp_desc}]},
    Msg = #ofp_message{version = ?V5, xid=2, body = Body},
    Res = of_msg_lib:decode(Msg),
    ?assertEqual(Expect, Res).

dec_aggregate_stats_reply() ->
    Flags = [],
    Packet_count = 10,
    Byte_count = 100,
    Flow_count = 3,
    Body = #ofp_aggregate_stats_reply{
              flags = Flags,
              packet_count = Packet_count,
              byte_count = Byte_count,
              flow_count = Flow_count
             },
    Expect = {aggregate_stats_reply, 2, [{flags, Flags},
                                         {packet_count, Packet_count},
                                         {byte_count, Byte_count},
                                         {flow_count, Flow_count}]},
    Msg = #ofp_message{version = ?V5, xid=2, body = Body},
    Res = of_msg_lib:decode(Msg),
    ?assertEqual(Expect, Res).

dec_group_features_reply() ->
    Flags = [],
    Types = [all,
             select,
             indirect,
             ff],
    Capabilities = [select_weight,
                    select_liveness,
                    chaining,
                    chaining_checks],
    Max_groups = {1,2,3,4},
    ActionSet = [copy_ttl_in,
                 pop_mpls,
                 pop_pbb,
                 pop_vlan,
                 push_mpls,
                 push_pbb,
                 push_vlan,
                 copy_ttl_out,
                 dec_mpls_ttl,
                 dec_nw_ttl,
                 set_mpls_ttl,
                 set_nw_ttl,
                 set_field,
                 set_queue,
                 group,
                 output,
                 experimenter],
    Actions = {ActionSet,ActionSet,ActionSet,ActionSet},
    Body = #ofp_group_features_reply{
              flags = Flags,
              types = Types,
              capabilities = Capabilities,
              max_groups = Max_groups,
              actions = Actions
             },
    Expect = {group_features_reply, 2, [{flags, Flags},
                                     {types, Types},
                                     {capabilities, Capabilities},
                                     {max_groups, Max_groups},
                                     {actions, Actions}]},
    Msg = #ofp_message{version = ?V5, xid=2, body = Body},
    Res = of_msg_lib:decode(Msg),
    ?assertEqual(Expect, Res).

dec_meter_features_reply() ->
    Flags = [],
    Max_meter = 20,
    Band_types = [drop,
                  dscp_remark,
                  experimenter],
    Capabilities = [kbps,
                    pktps,
                    burst,
                    stats],
    Max_bands = 20,
    Max_color = 30,
    Body = #ofp_meter_features_reply{
              flags = Flags,
              max_meter = Max_meter,
              band_types = Band_types,
              capabilities = Capabilities,
              max_bands = Max_bands,
              max_color = Max_color
             },
    Expect = {meter_features_reply, 2, [{flags, Flags},
                                        {max_meter, Max_meter},
                                        {band_types, Band_types},
                                        {capabilities, Capabilities},
                                        {max_bands, Max_bands},
                                        {max_color, Max_color}]},
    Msg = #ofp_message{version = ?V5, xid=2, body = Body},
    Res = of_msg_lib:decode(Msg),
    ?assertEqual(Expect, Res).

dec_experimenter_reply() ->
    Flags = [],
    Experimenter = 33,
    Exp_type = 2,
    Data = <<1,2,3,4,5>>,
    Body = #ofp_experimenter_reply{
          flags = Flags,
          experimenter = Experimenter,
          exp_type = Exp_type,
          data = Data
         },
    Expect = {experimenter_reply, 2, [{flags, Flags},
                                      {experimenter, Experimenter},
                                      {exp_type, Exp_type},
                                      {data, Data}]},
    Msg = #ofp_message{version = ?V5, xid=2, body = Body},
    Res = of_msg_lib:decode(Msg),
    ?assertEqual(Expect, Res).

dec_queue_get_config_reply() ->
    QueueId = 6,
    PortNo = 2,
    Queues = [#ofp_packet_queue{
                 queue_id = QueueId,
                 port_no = PortNo,
                 properties = [#ofp_queue_prop_min_rate{ rate = 2048 },
                               #ofp_queue_prop_max_rate{ rate = 4096 },
                               #ofp_queue_prop_experimenter{
                                  experimenter = 22,
                                  data = <<2,2,2,2,2,2,2>>
                                 }]}],
    Body = #ofp_queue_get_config_reply{
              port = PortNo,
              queues = Queues
             },
    ExpQueues = [[{queue_id, QueueId},
                  {port_no, PortNo},
                  {properties, [{min_rate, 2048},
                                {max_rate,4096},
                                {experimenter, 22, <<2,2,2,2,2,2,2>>}]}]],
    Expect = {queue_get_config_reply, 2, [{port, PortNo},
                                          {queues, ExpQueues}]},
    Msg = #ofp_message{version = ?V5, xid=2, body = Body},
    Res = of_msg_lib:decode(Msg),
    ?assertEqual(Expect, Res).

dec_barrier_reply() ->
    Body = #ofp_barrier_reply{},
    Expect = {barrier_reply, 2, []},
    Msg = #ofp_message{version = ?V5, xid=2, body = Body},
    Res = of_msg_lib:decode(Msg),
    ?assertEqual(Expect, Res).

dec_role_reply() ->
    Role = 0,
    Generation_id = 0,
    Body = #ofp_role_reply{
              role = Role,
              generation_id = Generation_id
         },
    Expect = {role_reply, 2, [{role, Role},
                              {generation_id, Generation_id}]},

    Msg = #ofp_message{version = ?V5, xid=2, body = Body},
    Res = of_msg_lib:decode(Msg),
    ?assertEqual(Expect, Res).

dec_get_async_reply() ->
    PacketInReason = [no_match,
                      action,
                      invalid_ttl],
    PortStatusMask = [add,
                      delete,
                      modify],
    FlowRemovedMask = [idle_timeout,
                       hard_timeout,
                       delete,
                       group_delete],
    Packet_in_mask = {PacketInReason, PacketInReason},
    Port_status_mask = {PortStatusMask, PortStatusMask},
    Flow_removed_mask = {FlowRemovedMask, FlowRemovedMask},
    Body = #ofp_get_async_reply{
          packet_in_mask = Packet_in_mask,
          port_status_mask = Port_status_mask,
          flow_removed_mask = Flow_removed_mask
         },
    Expect = {get_async_reply, 2, [{packet_in_mask, Packet_in_mask},
                                   {port_status_mask, Port_status_mask},
                                   {flow_removed_mask, Flow_removed_mask}]},
    Msg = #ofp_message{version = ?V5, xid=2, body = Body},
    Res = of_msg_lib:decode(Msg),
    ?assertEqual(Expect, Res).

dec_flow_stats_reply() ->
    Flags = [],
    Stats = [#ofp_flow_stats{
                table_id = 2,
                duration_sec = 123445566,
                duration_nsec = 2223,
                priority = 10,
                idle_timeout = 30000,
                hard_timeout = 90000,
                flags = [send_flow_rem],
                cookie = <<1,2,3,4,5,6>>,
                packet_count = 24000,
                byte_count = 200000,
                match = #ofp_match{ fields = [#ofp_field{name = in_port, value = 6},
                                              #ofp_field{name = eth_dst,
                                                         value = <<0,0,0,0,0,8>>}]},
                instructions = [#ofp_instruction_write_actions{
                                   actions = [#ofp_action_group{group_id = 3}]}]
               }],
    Body = #ofp_flow_stats_reply{ flags = Flags,
                                  body = Stats },
    ExpFlows = [[{table_id, 2},
                 {duration_sec, 123445566},
                 {duration_nsec, 2223},
                 {priority, 10},
                 {idle_timeout, 30000},
                 {hard_timeout, 90000},
                 {flags, [send_flow_rem]},
                 {cookie, <<1,2,3,4,5,6>>},
                 {packet_count, 24000},
                 {byte_count, 200000},
                 {match, [{in_port,6}, {eth_dst,<<0,0,0,0,0,8>>}]},
                 {instructions, [{write_actions,[{group_id,3}]}]}]],
    Expect = {flow_stats_reply, 2, [{flags, Flags},
                                    {flows, ExpFlows}]},
    Msg = #ofp_message{version = ?V5, xid=2, body = Body},
    Res = of_msg_lib:decode(Msg),
    ?assertEqual(Expect, Res).

dec_table_stats_reply() ->
    Flags = [],
    Stats = [#ofp_table_stats{
                table_id = 10,
                active_count =  256,
                lookup_count = 2345,
                matched_count = 99
               }],
    ExpStats = [[{table_id, 10},
                 {active_count, 256},
                 {lookup_count, 2345},
                 {matched_count, 99}]],
    Body = #ofp_table_stats_reply{ flags = Flags,
                                   body = Stats },
    Expect = {table_stats_reply, 2, [{flags, Flags},
                                     {tables, ExpStats}]},
    Msg = #ofp_message{version = ?V5, xid=2, body = Body},
    Res = of_msg_lib:decode(Msg),
    ?assertEqual(Expect, Res).

-define(SUPPORTED_METADATA_MATCH, <<-1:64>>).
-define(SUPPORTED_METADATA_WRITE, <<-1:64>>).
-define(MAX_FLOW_TABLE_ENTRIES, 128).
-define(SUPPORTED_INSTRUCTIONS, [goto_table,
                                 write_metadata,
                                 write_actions,
                                 apply_actions,
                                 clear_actions,
                                 meter]).
-define(SUPPORTED_ACTIONS, [output,
                            group,
                            set_queue,
                            set_mpls_ttl,
                            dec_mpls_ttl,
                            set_nw_ttl,
                            dec_nw_ttl,
                            copy_ttl_out,
                            copy_ttl_in,
                            push_vlan,
                            pop_vlan,
                            push_mpls,
                            pop_mpls,
                            push_pbb,
                            pop_pbb,
                            set_field
                           ]).
-define(SUPPORTED_MATCH_FIELDS, [in_port,
                                 %% in_phy_port,
                                 metadata,
                                 eth_dst,
                                 eth_src,
                                 eth_type,
                                 vlan_vid,
                                 vlan_pcp,
                                 ip_dscp,
                                 ip_ecn,
                                 ip_proto,
                                 ipv4_src,
                                 ipv4_dst,
                                 tcp_src,
                                 tcp_dst,
                                 udp_src,
                                 udp_dst,
                                 sctp_src,
                                 sctp_dst,
                                 icmpv4_type,
                                 icmpv4_code,
                                 arp_op,
                                 arp_spa,
                                 arp_tpa,
                                 arp_sha,
                                 arp_tha,
                                 ipv6_src,
                                 ipv6_dst,
                                 ipv6_flabel,
                                 icmpv6_type,
                                 icmpv6_code,
                                 ipv6_nd_target,
                                 ipv6_nd_sll,
                                 ipv6_nd_tll,
                                 mpls_label,
                                 mpls_tc,
                                 mpls_bos,
                                 pbb_isid
                                 %% tunnel_id
                                 %% ext_hdr
                                ]).
-define(SUPPORTED_WILDCARDS, ?SUPPORTED_MATCH_FIELDS).
-define(SUPPORTED_WRITE_SETFIELDS, ?SUPPORTED_MATCH_FIELDS).
-define(SUPPORTED_APPLY_SETFIELDS, ?SUPPORTED_WRITE_SETFIELDS).

dec_table_features_reply() ->
    Flags = [],
    TableId = 3,
    TableName = <<"Flow Table 3">>,
    Features = [#ofp_table_features{
                   table_id = TableId,
                   name = TableName,
                   metadata_match = ?SUPPORTED_METADATA_MATCH,
                   metadata_write = ?SUPPORTED_METADATA_WRITE,
                   max_entries = ?MAX_FLOW_TABLE_ENTRIES,
                   properties = [#ofp_table_feature_prop_instructions{
                                    instruction_ids = ?SUPPORTED_INSTRUCTIONS},
                                 #ofp_table_feature_prop_instructions_miss{
                                     instruction_ids = ?SUPPORTED_INSTRUCTIONS},
                                 #ofp_table_feature_prop_next_tables{
                                     next_table_ids = lists:seq(TableId+1,?OFPTT_MAX)},
                                 #ofp_table_feature_prop_next_tables_miss{
                                     next_table_ids = lists:seq(TableId+1,?OFPTT_MAX)},
                                 #ofp_table_feature_prop_write_actions{
                                     action_ids = ?SUPPORTED_ACTIONS},
                                 #ofp_table_feature_prop_write_actions_miss{
                                     action_ids = ?SUPPORTED_ACTIONS},
                                 #ofp_table_feature_prop_apply_actions{
                                     action_ids = ?SUPPORTED_ACTIONS},
                                 #ofp_table_feature_prop_apply_actions_miss{
                                     action_ids = ?SUPPORTED_ACTIONS},
                                 #ofp_table_feature_prop_match{
                                     oxm_ids = ?SUPPORTED_MATCH_FIELDS},
                                 #ofp_table_feature_prop_wildcards{
                                     oxm_ids = ?SUPPORTED_WILDCARDS},
                                 #ofp_table_feature_prop_write_setfield{
                                    oxm_ids = ?SUPPORTED_WRITE_SETFIELDS},
                                 #ofp_table_feature_prop_write_setfield_miss{
                                    oxm_ids = ?SUPPORTED_WRITE_SETFIELDS},
                                 #ofp_table_feature_prop_apply_setfield{
                                    oxm_ids = ?SUPPORTED_APPLY_SETFIELDS},
                                 #ofp_table_feature_prop_apply_setfield_miss{
                                    oxm_ids = ?SUPPORTED_APPLY_SETFIELDS}
                                ]}],
    ExpFeatures = [
                    [
                      {table_id, TableId},
                      {name, TableName},
                      {metadata_match, ?SUPPORTED_METADATA_MATCH},
                      {metadata_write, ?SUPPORTED_METADATA_WRITE},
                      {max_entries, ?MAX_FLOW_TABLE_ENTRIES},
                      {properties,[ {instructions,  ?SUPPORTED_INSTRUCTIONS},
                                    {instructions_miss,  ?SUPPORTED_INSTRUCTIONS},
                                    {next_tables, lists:seq(TableId+1,?OFPTT_MAX)},
                                    {next_tables_miss, lists:seq(TableId+1,?OFPTT_MAX)},
                                    {write_actions, ?SUPPORTED_ACTIONS},
                                    {write_actions_miss, ?SUPPORTED_ACTIONS},
                                    {apply_actions, ?SUPPORTED_ACTIONS},
                                    {apply_actions_miss, ?SUPPORTED_ACTIONS},
                                    {match, ?SUPPORTED_MATCH_FIELDS},
                                    {wildcards, ?SUPPORTED_WILDCARDS},
                                    {write_setfield, ?SUPPORTED_WRITE_SETFIELDS},
                                    {write_setfield_miss, ?SUPPORTED_WRITE_SETFIELDS},
                                    {apply_setfield, ?SUPPORTED_APPLY_SETFIELDS},
                                    {apply_setfield_miss, ?SUPPORTED_APPLY_SETFIELDS}
                                  ]}
                    ]
                  ],
    Body = #ofp_table_features_reply{ flags = Flags,
                                      body = Features },
    Expect = {table_features_reply, 2, [{flags, Flags},
                                        {tables, ExpFeatures}]},
    Msg = #ofp_message{version = ?V5, xid=2, body = Body},
    Res = of_msg_lib:decode(Msg),
    ?assertEqual(Expect, Res).

dec_port_stats_reply() ->
    Flags = [],
    Port_no = 1001,
    Rx_packets = 1002,
    Tx_packets = 1003,
    Rx_bytes = 1004,
    Tx_bytes = 1005,
    Rx_dropped = 1006,
    Tx_dropped = 1007,
    Rx_errors = 1008,
    Tx_errors = 1009,
    Rx_frame_err = 10010,
    Rx_over_err = 10011,
    Rx_crc_err = 10012,
    Collisions = 10013,
    Duration_sec = 10014,
    Duration_nsec = 10015,

    Tx_freq_lmda = 10015,
    Tx_offset = 10016,
    Tx_grid_span = 10017,
    Rx_freq_lmda = 10018,
    Rx_offset = 10019,
    Rx_grid_span = 10020,
    Tx_pwr = 10021,
    Rx_pwr = 10022,
    Bias_current = 10023,
    Temperature = 10024,

    Experimenter = 1,
    Exp_type = 1,
    Data = <<1,2,3,4,5,6,7,8>>,

    RecProperties = [#ofp_port_stats_prop_ethernet{rx_frame_err = Rx_frame_err,
                                                   rx_over_err = Rx_over_err,
                                                   rx_crc_err = Rx_crc_err,
                                                   collisions = Collisions},
                     #ofp_port_stats_prop_optical{flags = Flags,
                                                  tx_freq_lmda = Tx_freq_lmda,
                                                  tx_offset = Tx_offset,
                                                  tx_grid_span = Tx_grid_span,
                                                  rx_freq_lmda = Rx_freq_lmda,
                                                  rx_offset = Rx_offset,
                                                  rx_grid_span = Rx_grid_span,
                                                  tx_pwr = Tx_pwr,
                                                  rx_pwr = Rx_pwr,
                                                  bias_current = Bias_current,
                                                  temperature = Temperature},
                     #ofp_port_stats_prop_experimenter{experimenter = Experimenter,
                                                       exp_type = Exp_type,
                                                       data = Data}
    ],

    Ports = [#ofp_port_stats{
                port_no = Port_no,
                duration_sec = Duration_sec,
                duration_nsec = Duration_nsec,
                rx_packets = Rx_packets,
                tx_packets = Tx_packets,
                rx_bytes = Rx_bytes,
                tx_bytes = Tx_bytes,
                rx_dropped = Rx_dropped,
                tx_dropped = Tx_dropped,
                rx_errors = Rx_errors,
                tx_errors = Tx_errors,
                properties = RecProperties
            }],

    Properties = [
        [{rx_frame_err , Rx_frame_err},
         {rx_over_err , Rx_over_err},
         {rx_crc_err , Rx_crc_err},
         {collisions , Collisions}],
        [{flags, Flags},
         {tx_freq_lmda, Tx_freq_lmda},
         {tx_offset, Tx_offset},
         {tx_grid_span, Tx_grid_span},
         {rx_freq_lmda, Rx_freq_lmda},
         {rx_offset, Rx_offset},
         {rx_grid_span, Rx_grid_span},
         {tx_pwr, Tx_pwr},
         {rx_pwr, Rx_pwr},
         {bias_current, Bias_current},
         {temperature, Temperature}],
        [{experimenter, Experimenter},
         {exp_type, Exp_type},
         {data, Data}]
    ],
    ExpStats = [[{port_no, Port_no},
                 {duration_sec, Duration_sec},
                 {duration_nsec, Duration_nsec},
                 {rx_packets, Rx_packets},
                 {tx_packets, Tx_packets},
                 {rx_bytes, Rx_bytes},
                 {tx_bytes, Tx_bytes},
                 {rx_dropped, Rx_dropped},
                 {tx_dropped, Tx_dropped},
                 {rx_errors, Rx_errors},
                 {tx_errors, Tx_errors},
                 {properties,Properties}]],

    Body = #ofp_port_stats_reply{ flags = Flags,
                                  body = Ports },
    Expect = {port_stats_reply, 2, [{flags, Flags},
                                    {ports, ExpStats}]},
    Msg = #ofp_message{version = ?V5, xid=2, body = Body},
    Res = of_msg_lib:decode(Msg),
    ?assertEqual(Expect, Res).


% test/of_msg_lib_v5_tests.erl:1097: field curr undefined in record ofp_port
% test/of_msg_lib_v5_tests.erl:1098: field advertised undefined in record ofp_port
% test/of_msg_lib_v5_tests.erl:1099: field supported undefined in record ofp_port
% test/of_msg_lib_v5_tests.erl:1100: field peer undefined in record ofp_port
% test/of_msg_lib_v5_tests.erl:1101: field curr_speed undefined in record ofp_port
% test/of_msg_lib_v5_tests.erl:1102: field max_speed undefined in record ofp_port
dec_port_desc_reply() ->
    Flags = [],
    Port_no = 24,
    Hw_addr = <<1,2,3,4,5,6>>,
    Name = <<"Port24">>,
    Config = [port_down,
              no_recv,
              no_fwd,
              no_packet_in],
    State = [link_down,
             blocked,
             live],
    Curr = ['100mb_hd'],
    Advertised = ['100mb_hd'],
    Supported = ['100mb_hd'],
    Peer = ['100mb_hd'],
    Curr_speed = 100,
    Max_speed = 1000,

    Properties = [ #ofp_port_desc_prop_ethernet{
                    curr = Curr,
                    advertised = Advertised,
                    supported = Supported,
                    peer = Peer,
                    curr_speed = Curr_speed,
                    max_speed = Max_speed 
                   },
                   #ofp_port_desc_prop_optical{
                         supported = [rx_tune],
                         tx_min_freq_lmda = 1,
                         tx_max_freq_lmda = 2,
                         tx_grid_freq_lmda = 3,
                         rx_min_freq_lmda = 4,
                         rx_max_freq_lmda = 5,
                         rx_grid_freq_lmda = 6,
                         tx_pwr_min = 7,
                         tx_pwr_max = 8
                   },
                   #ofp_port_desc_prop_experimenter{
                        experimenter =9,
                        exp_type =10,
                        data = <<1,2,3,4,5,6,7,8>>
                   }
    ],
    Ports = [#ofp_port{
                port_no = Port_no,
                hw_addr = Hw_addr,
                name = Name,
                config = Config,
                state = State,
                properties = Properties
               }],

    DecProperties = [
        [{curr,Curr},
         {advertised,Advertised},
         {supported,Supported},
         {peer,Peer},
         {curr_speed,Curr_speed},
         {max_speed,Max_speed} ],
        [{supported,[rx_tune]},
         {tx_min_freq_lmda,1},
         {tx_max_freq_lmda,2},
         {tx_grid_freq_lmda,3},
         {rx_min_freq_lmda,4},
         {rx_max_freq_lmda,5},
         {rx_grid_freq_lmda,6},
         {tx_pwr_min,7},
         {tx_pwr_max,8}],
        [{experimenter,9},
         {exp_type,10},
         {data,<<1,2,3,4,5,6,7,8>>}]
    ],
    ExpPorts = [[{port_no, Port_no},
                 {hw_addr, Hw_addr},
                 {name, Name},
                 {config, Config},
                 {state, State},
                 {properties,DecProperties}
               ]],
    Body = #ofp_port_desc_reply{ flags = Flags,
                                 body = Ports },
    Expect = {port_desc_reply, 2, [{flags, Flags},
                                   {ports, ExpPorts}]},
    Msg = #ofp_message{version = ?V5, xid=2, body = Body},
    Res = of_msg_lib:decode(Msg),
    ?assertEqual(Expect, Res).

dec_queue_stats_reply() ->
    Flags = [],
    Port_no = 3,
    Queue_id = 7,
    Tx_bytes = 10234,
    Tx_packets = 245,
    Tx_errors = 4,
    Duration_sec = 1223456,
    Duration_nsec = 12345,
    Properties = [#ofp_queue_stats_prop_experimenter{ experimenter = 1, 
                                                      exp_type = 2,
                                                      data = <<1,2,3,4,5,6,7,8>>}],
    Queues = [#ofp_queue_stats{
                 port_no = Port_no,
                 queue_id = Queue_id,
                 tx_bytes = Tx_bytes,
                 tx_packets = Tx_packets,
                 tx_errors = Tx_errors,
                 duration_sec = Duration_sec,
                 duration_nsec = Duration_nsec,
                 properties = Properties
                }],
    DecProperties = [
                     [{experimenter,1}, 
                     {exp_type,2},
                     {data,<<1,2,3,4,5,6,7,8>>}]
                    ],
    ExpQueues = [[{port_no, Port_no},
                  {queue_id, Queue_id},
                  {tx_bytes, Tx_bytes},
                  {tx_packets, Tx_packets},
                  {tx_errors, Tx_errors},
                  {duration_sec, Duration_sec},
                  {duration_nsec, Duration_nsec},
                  {properties,DecProperties}]],
    Body = #ofp_queue_stats_reply{ flags = Flags,
                                   body = Queues },
    Expect = {queue_stats_reply,2, [{flags, Flags},
                                    {queues, ExpQueues}]},
    Msg = #ofp_message{version = ?V5, xid=2, body = Body},
    Res = of_msg_lib:decode(Msg),
    io:format("~p\n",[Res]),
    
    ?assertEqual(Expect, Res).

dec_group_stats_reply() ->
    Flags = [],
    BucketsPs1 = 123,
    BucketBs1 = 234,
    BucketsPs2 = 345,
    BucketBs2 = 456,
    BucketStats = [#ofp_bucket_counter{
                      packet_count = BucketsPs1,
                      byte_count   = BucketBs1},
                   #ofp_bucket_counter{
                      packet_count = BucketsPs2,
                      byte_count   = BucketBs2
                     }],
    Group_id = 2,
    Ref_count = 4,
    Packet_count = 567,
    Byte_count = 687,
    Duration_sec = 12345,
    Duration_nsec = 4567889,
    Groups = [#ofp_group_stats{
                 group_id = Group_id,
                 ref_count = Ref_count,
                 packet_count = Packet_count,
                 byte_count = Byte_count,
                 duration_sec = Duration_sec,
                 duration_nsec = Duration_nsec,
                 bucket_stats = BucketStats
                }],
    Body = #ofp_group_stats_reply{ flags = Flags,
                                   body = Groups },
    ExpStats = [[{group_id, Group_id},
                 {ref_count, Ref_count},
                 {packet_count, Packet_count},
                 {byte_count, Byte_count},
                 {duration_sec, Duration_sec},
                 {duration_nsec, Duration_nsec},
                 {bucket_stats, [[{packet_count, BucketsPs1},
                                  {byte_count, BucketBs1}],
                                 [{packet_count, BucketsPs2},
                                  {byte_count, BucketBs2}]]}]],
    Expect = {group_stats_reply, 2, [{flags, Flags},
                                     {groups, ExpStats}]},
    Msg = #ofp_message{version = ?V5, xid=2, body = Body},
    Res = of_msg_lib:decode(Msg),
    ?assertEqual(Expect, Res).

dec_group_desc_reply() ->
    Flags = [],
    Type = all,
    Group_id = 23,
    Buckets = [#ofp_bucket{
                  weight = 1,
                  watch_port = 3,
                  watch_group = 4,
                  actions = [#ofp_action_pop_mpls{ethertype = 234}]
                 }],
    Groups = [#ofp_group_desc_stats{
                 type = Type,
                 group_id = Group_id,
                 buckets = Buckets
                }],
    Body = #ofp_group_desc_reply{ flags = Flags,
                                  body = Groups },
    ExpDesc = [[
                {type, Type},
                {group_id, Group_id},
                {buckets, [[{weight, 1},
                            {watch_port, 3},
                            {watch_group, 4},
                            {actions, [{pop_mpls, 234}]}
                           ]]}]],
    Expect = {group_desc_reply, 2, [{flags, Flags},
                                    {groups, ExpDesc}]},
    Msg = #ofp_message{version = ?V5, xid=2, body = Body},
    Res = of_msg_lib:decode(Msg),
    ?assertEqual(Expect, Res).

dec_meter_stats_reply() ->
    Flags = [],
    Meters = [#ofp_meter_stats{
                 meter_id = 3,
                 flow_count = 4,
                 packet_in_count = 5,
                 byte_in_count = 5,
                 duration_sec = 7,
                 duration_nsec = 9,
                 band_stats = [#ofp_meter_band_stats{
                                  packet_band_count = 45,
                                  byte_band_count = 67}]}],
    Body = #ofp_meter_stats_reply{ flags = Flags,
                                   body = Meters},
    ExpMeters = [[{meter_id, 3},
                 {flow_count, 4},
                 {packet_in_count, 5},
                 {byte_in_count, 5},
                 {duration_sec, 7},
                 {duration_nsec, 9},
                 {band_stats, [[{packet_band_count, 45},
                                 {byte_band_count, 67}]]}]],

    Expect = {meter_stats_reply, 2, [{flags, Flags},
                                     {meters, ExpMeters}]},
    Msg = #ofp_message{version = ?V5, xid=2, body = Body},
    Res = of_msg_lib:decode(Msg),
    ?assertEqual(Expect, Res).

dec_meter_config_reply() ->
    Flags = [],
    Bands = [#ofp_meter_band_drop{
                rate = 123,
                burst_size = 9999
               }],
    Meters = [#ofp_meter_config{
                 flags = [add],
                 meter_id = 3,
                 bands = Bands}],
    Body = #ofp_meter_config_reply{ flags = Flags,
                                    body = Meters },
    ExpMeters = [[{flags, [add]},
                  {meter_id, 3},
                  {bands, [[{type, drop},
                            {rate, 123},
                            {burst_size, 9999}
                           ]]}]],

    Expect = {meter_config_reply, 2, [{flags, Flags},
                                      {meters, ExpMeters}]},

    Msg = #ofp_message{version = ?V5, xid=2, body = Body},
    Res = of_msg_lib:decode(Msg),
    ?assertEqual(Expect, Res).

dec_packet_in() ->
    Buffer_id = 0,
    Reason = 0,
    Table_id = 0,
    Cookie = 0,
    Data = <<"data data data">>,
    Match = #ofp_match{ fields = [#ofp_field{name = in_port, value = 6},
                                  #ofp_field{name = eth_dst,
                                             value = <<0,0,0,0,0,8>>}]},
    Body = #ofp_packet_in{
          buffer_id = Buffer_id,
          reason = Reason,
          table_id = Table_id,
          cookie = Cookie,
          match = Match,
          data = Data
         },
    ExpMatch = [{in_port,6}, {eth_dst,<<0,0,0,0,0,8>>}],
    Expect = {packet_in, 2, [{buffer_id, Buffer_id},
                             {reason, Reason},
                             {table_id, Table_id},
                             {cookie, Cookie},
                             {match, ExpMatch},
                             {data, Data}]},

    Msg = #ofp_message{version = ?V5, xid=2, body = Body},
    Res = of_msg_lib:decode(Msg),
    ?assertEqual(Expect, Res).

dec_flow_removed() ->
    Cookie = <<1,2,3,4,5,6>>,
    Priority = 2,
    Reason = delete,
    Table_id = 3,
    Duration_sec = 23,
    Duration_nsec = 456,
    Idle_timeout = 333,
    Hard_timeout = 444,
    Packet_count = 45567,
    Byte_count = 3456,
    Match = #ofp_match{ fields = [#ofp_field{name = in_port, value = 6},
                                  #ofp_field{name = eth_dst,
                                             value = <<0,0,0,0,0,8>>}]},
    Body = #ofp_flow_removed{
          cookie = Cookie,
          priority = Priority,
          reason = Reason,
          table_id = Table_id,
          duration_sec = Duration_sec,
          duration_nsec = Duration_nsec,
          idle_timeout = Idle_timeout,
          hard_timeout = Hard_timeout,
          packet_count = Packet_count,
          byte_count = Byte_count,
          match = Match
         },
    ExpMatch = [{in_port,6}, {eth_dst,<<0,0,0,0,0,8>>}],
    Expect = {flow_removed, 2, [{cookie, Cookie},
                                {priority, Priority},
                                {reason, Reason},
                                {table_id, Table_id},
                                {duration_sec, Duration_sec},
                                {duration_nsec, Duration_nsec},
                                {idle_timeout, Idle_timeout},
                                {hard_timeout, Hard_timeout},
                                {packet_count, Packet_count},
                                {byte_count, Byte_count},
                                {match, ExpMatch}]},
    Msg = #ofp_message{version = ?V5, xid=2, body = Body},
    Res = of_msg_lib:decode(Msg),
    ?assertEqual(Expect, Res).

dec_port_status() ->
    Reason = modify,
    Port_no = 24,
    Hw_addr = <<1,2,3,4,5,6>>,
    Name = <<"Port24">>,
    Config = [port_down,
              no_recv,
              no_fwd,
              no_packet_in],
    State = [link_down,
             blocked,
             live],
    Curr = ['100mb_hd'],
    Advertised = ['100mb_hd'],
    Supported = ['100mb_hd'],
    Peer = ['100mb_hd'],
    Curr_speed = 100,
    Max_speed = 1000,
    Experimenter = 1,
    Exp_type = 2,
    Data = <<1,2,3,4,5,6,7,8>>,

    Properties = [#ofp_port_desc_prop_ethernet{curr = Curr,
                                               advertised = Advertised,
                                               supported = Supported,
                                               peer = Peer,
                                               curr_speed = Curr_speed,
                                               max_speed = Max_speed},
                  #ofp_port_desc_prop_optical{
                         supported = [rx_tune],
                         tx_min_freq_lmda = 112,
                         tx_max_freq_lmda = 113,
                         tx_grid_freq_lmda = 114,
                         rx_min_freq_lmda = 115,
                         rx_max_freq_lmda = 116,
                         rx_grid_freq_lmda = 117,
                         tx_pwr_min = 118,
                         tx_pwr_max = 119
                   },
                  #ofp_port_desc_prop_experimenter{ experimenter = Experimenter, 
                                                    exp_type = Exp_type,
                                                    data = Data }
                 ],

    Desc = #ofp_port{
              port_no = Port_no,
              hw_addr = Hw_addr,
              name = Name,
              config = Config,
              state = State,
              properties = Properties
             },
    DecProperties =
        [
        [{curr,Curr},
         {advertised,Advertised},
         {supported,Supported},
         {peer,Peer},
         {curr_speed,Curr_speed},
         {max_speed,Max_speed} ],
        [{supported,[rx_tune]},
         {tx_min_freq_lmda,112},
         {tx_max_freq_lmda,113},
         {tx_grid_freq_lmda,114},
         {rx_min_freq_lmda,115},
         {rx_max_freq_lmda,116},
         {rx_grid_freq_lmda,117},
         {tx_pwr_min,118},
         {tx_pwr_max,119}],
        [{experimenter, Experimenter},
         {exp_type, Exp_type},
         {data, Data}]
    ],
    ExpDesc = [{port_no, Port_no},
                {hw_addr, Hw_addr},
                {name, Name},
                {config, Config},
                {state, State},
                {properties,DecProperties}],
    Body = #ofp_port_status{
              reason = Reason,
              desc = Desc
         },
    Expect = {port_status, 2, [{reason, Reason},
                               {desc, ExpDesc}]},
    Msg = #ofp_message{version = ?V5, xid=2, body = Body},
    Res = of_msg_lib:decode(Msg),
    ?assertEqual(Expect, Res).

dec_error_msg() ->
    Type = bad_request,
    Code = bad_multipart,
    Data = <<1>>,
    Body = #ofp_error_msg{
          type = Type,
          code = Code,
          data = Data
             },
    Expect = {error_msg, 2, [{type, Type},
                             {code, Code},
                             {data, Data}]},
    Msg = #ofp_message{version = ?V5, xid=2, body = Body},
    Res = of_msg_lib:decode(Msg),
    ?assertEqual(Expect, Res).

dec_error_msg_experimenter() ->
    Exp_type = 1,
    Experimenter = 2,
    Data = <<1,2,3>>,
    Body =#ofp_error_msg_experimenter{
          exp_type = Exp_type,
          experimenter = Experimenter,
          data = Data
            },
    Expect = {error_msg_experimenter, 2, [{exp_type, Exp_type},
                                          {experimenter, Experimenter},
                                          {data, Data}]},
    Msg = #ofp_message{version = ?V5, xid=2, body = Body},
    Res = of_msg_lib:decode(Msg),
    ?assertEqual(Expect, Res).

dec_echo_request() ->
    Data = <<"Random noise">>,
    Body = #ofp_echo_request{ data = Data },
    Expect = {echo_request, 2, [{data, Data}]},
    Msg = #ofp_message{version = ?V5, xid=2, body = Body},
    Res = of_msg_lib:decode(Msg),
    ?assertEqual(Expect, Res).

dec_echo_reply() ->
    Data = <<"Random noise">>,
    Body = #ofp_echo_request{ data = Data },
    Expect = {echo_request, 2, [{data, Data}]},
    Msg = #ofp_message{version = ?V5, xid=2, body = Body},
    Res = of_msg_lib:decode(Msg),
    ?assertEqual(Expect, Res).

dec_experimenter() ->
    Experimenter = 0,
    Exp_type = 0,
    Data = 0,
    Body = #ofp_experimenter{
              experimenter = Experimenter,
              exp_type = Exp_type,
              data = Data
             },
        Expect = {experimenter, 2, [{experimenter, Experimenter},
                                    {exp_type, Exp_type},
                                    {data, Data}]},
    Msg = #ofp_message{version = ?V5, xid=2, body = Body},
    Res = of_msg_lib:decode(Msg),
    ?assertEqual(Expect, Res).

%%% ==================================================================

encode_decode_rf(?V5, Msg) ->
    Bin = ofp_v5_encode:do(Msg),
    {ok,  Msg1, <<>>} = ofp_v5_decode:do(Bin),
    #ofp_message{ body = Body } = Msg1,
    #ofp_requestforward{ request = Request } = Body,
    Request1 = Request#ofp_message{ type = undefined },
    Body1 = Body#ofp_requestforward{ request = Request1 },
    Msg1#ofp_message{ type = undefined, body = Body1 }.

encode_decode_ba(?V5,Msg) ->
    Bin = ofp_v5_encode:do(Msg),
    {ok,  Msg1, <<>>} = ofp_v5_decode:do(Bin),
    #ofp_message{ body = Body } = Msg1,
    #ofp_bundle_add_msg{ message = Message } = Body,
    Message1 = Message#ofp_message{ type = undefined },
    Body1 = Body#ofp_bundle_add_msg{ message = Message1 },
    Msg1#ofp_message{ type = undefined, body = Body1 }.

encode_decode(?V5, Msg) ->
    Bin = ofp_v5_encode:do(Msg),
    {ok,  Msg1, <<>>} = ofp_v5_decode:do(Bin),
    Msg1#ofp_message{ type = undefined }.
