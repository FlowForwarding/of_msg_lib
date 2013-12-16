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

%%%-------------------------------------------------------------------
%%% @author Erlang Solutions Ltd. <openflow@erlang-solutions.com>
%%% @copyright (C) 2013, FlowForwarding.org
%%% @doc
%%% A library for creating OpenFlow messages compatible with of_protocol,
%%% https://github.com/FlowForwarding/of_protocol.
%%% @end
%%% Created : 26 Sep 2013 by Anders Nygren <anders.nygren@erlang-solutions.com>
%%%-------------------------------------------------------------------
-module(of_msg_lib).

%% API

-export([create_error/3,
         decode/1,
         hello/2,
         echo_request/2,
         get_features/1,
         get_config/1,
         set_config/3,
         send_packet/4,
         flow_add/4,
         flow_modify/4,
         flow_delete/3,
         group_add/4,
         group_modify/4,
         group_delete/3,
         set_port_up/3,
         set_port_down/3,
         set_port_recv/3,
         set_port_no_recv/3,
         set_port_fwd/3,
         set_port_no_fwd/3,
         set_port_packet_in/3,
         set_port_no_packet_in/3,
         get_description/1,
         get_flow_statistsics/4,
         get_aggregate_statistics/4,
         get_table_stats/1,
         get_table_features/1,
         set_table_features/2,
         get_port_descriptions/1,
         get_port_statistics/2,
         get_queue_statistics/3,
         get_group_statistics/2,
         get_group_descriptions/1,
         get_group_features/1,
         get_meter_stats/2,
         get_meter_configuration/2,
         get_meter_features/1,
         experimenter/4,
         barrier/1,
         get_queue_configuration/2,
         set_role/3,
         get_async_configuration/1,
         set_async_configuration/4,
         meter_add/4,
         meter_modify/4,
         meter_delete/2]).

-include_lib("of_protocol/include/of_protocol.hrl").

-define(V4, 4).

-type version()                :: ?V4.
-type supported_versions()     :: [?V4].
-type config_flags()           :: frag_normal
                                | frag_drop
                                | frag_reasm
                                | frag_mask.
-type max_len()                :: 0..16#FFE5.
-type miss_send_len()          :: max_len()
                                | no_buffer.
-type port_no()                :: non_neg_integer().
-type queue_id()               :: non_neg_integer().
-type group_id()               :: non_neg_integer().
-type group_type()             :: all
                                | select
                                | indirect
                                | ff.     %% Fast failover
-type weight()                 :: non_neg_integer().
-type bucket()                 :: {weight(), port_no(), group_id(), actions()}.
-type buckets()                :: [bucket()].

-type band_type()              :: drop
                                | dscp_remark.

-type rate()                   :: non_neg_integer().
-type burst_size()             :: non_neg_integer().
-type prec_level()             :: non_neg_integer().
-type meter_band()             :: {drop, rate(), burst_size()}
                                | {dscp_remark,  rate(), burst_size(), prec_level()}
                                | {experimenter,  band_type(), rate(), burst_size(), experimenter_id()}.
-type bands()                  :: [meter_band()].
-type meter_flag()             :: kbps
                                | pktps
                                | burst
                                | stats.
-type meter_flags()            :: [meter_flag()].
-type meter_id()               :: non_neg_integer().

-type table_id()                 :: 0..254.
-type table_ids()                :: [table_id()].
-type experimenter_id()          :: non_neg_integer().
-type exp_type()                 :: non_neg_integer().
-type ethertype()                :: non_neg_integer().
-type mac_addr()                 :: <<_:48>>.  %% 6 bytes
-type ttl()                      :: non_neg_integer().
-type action_id()                :: copy_ttl_in
                                  | pop_mpls
                                  | pop_pbb
                                  | pop_vlan
                                  | push_mpls
                                  | push_pbb
                                  | push_vlan
                                  | copy_ttl_out
                                  | dec_mpls_ttl
                                  | dec_nw_ttl
                                  | set_mpls_ttl
                                  | set_nw_ttl
                                  | set_field
                                  | set_queue
                                  | group
                                  | output
                                  | experimenter.
-type action_ids()               :: [action_id()].
-type action()                   :: copy_ttl_in
                                  | {pop_mpls, ethertype()}
                                  | pop_pbb
                                  | pop_vlan
                                  | {push_mpls, ethertype()}
                                  | {push_pbb, ethertype()}
                                  | {push_vlan, ethertype()}
                                  | copy_ttl_out
                                  | dec_mpls_ttl
                                  | dec_nw_ttl
                                  | {set_mpls_ttl, ttl()}
                                  | {set_nw_ttl, ttl()}
                                  | {set_field, field_name(), field_value()}
                                  | {set_queue, port_no(), queue_id()}
                                  | {group, group_id()}
                                  | {output, port_no(), max_len()}
                                  | {experimenter, experimenter_id(), binary()}.

-type actions()                  :: [action()].

-type field_name()               :: in_port
                                  | in_phy_port
                                  | metadata
                                  | eth_dst
                                  | eth_src
                                  | eth_type
                                  | vlan_vid
                                  | vlan_pcp
                                  | ip_dscp
                                  | ip_ecn
                                  | ip_proto
                                  | ipv4_src
                                  | ipv4_dst
                                  | tcp_src
                                  | tcp_dst
                                  | udp_src
                                  | udp_dst
                                  | sctp_src
                                  | sctp_dst
                                  | icmpv4_type
                                  | icmpv4_code
                                  | arp_op
                                  | arp_spa
                                  | arp_tpa
                                  | arp_sha
                                  | arp_tha
                                  | ipv6_src
                                  | ipv6_dst
                                  | ipv6_label
                                  | icmpv6_type
                                  | icmpv6_code
                                  | ipv6_nd_target
                                  | ipv6_nd_sll
                                  | ipv6_nd_tll
                                  | mpls_label
                                  | mpls_tc
                                  | mpls_bos
                                  | pbb_isid
                                  | tunnel_id
                                  | ipv6_exthdr.

-type fields()                   :: [field_name()].
-type field_value()              :: atom()
                                  | binary()
                                  | non_neg_integer().
-type field_mask()               :: binary().
-type match()                    :: {field_name(),field_value()}
                                  | {field_name(),field_value(), field_mask()}.
-type matches()                  :: [match()].

-type metadata()                 :: <<_:64>>.
-type metadata_mask()            :: <<_:64>>.
-type instruction()              :: {meter, meter_id()}
                                  | {apply_actions, actions()}
                                  | clear_actions
                                  | {write_actions, actions()}
                                  | {write_metadata, metadata(), metadata_mask()}
                                  | {goto_table, table_id()}
                                  | {experimenter, experimenter_id(), binary()}.

-type instructions()             :: [instruction()].
-type opt()                      :: x.
-type opts()                     :: [opt()].

-type role()                     :: nochange
                                  | equal
                                  | master
                                  | slave.
-type generation_id()            :: non_neg_integer().

-type table_name()               :: binary().
-type metadata_match()           :: <<_:64>>.
-type metadata_write()           :: <<_:64>>.
-type max_entries()              :: non_neg_integer().
-type table_feature_property()   :: {instructions, instructions()}
                                  | {instructions_miss, instructions()}
                                  | {next_tables, table_ids()}
                                  | {next_tables_miss, table_ids()}
                                  | {write_actions, action_ids()}
                                  | {write_actions_miss, action_ids()}
                                  | {apply_actions, action_ids()}
                                  | {apply_actions_miss, action_ids()}
                                  | {match, fields()}
                                  | {wildcards, fields()}
                                  | {write_setfield, fields()}
                                  | {write_setfield_miss, fields()}
                                  | {apply_setfield, fields()}
                                  | {apply_setfield_miss, fields()}
                                  | {experimenter, experimenter_id()}
                                  | {experimenter_miss, experimenter_id()}.

-type table_feature_properties() :: [table_feature_property()].

-type table_feature()            :: {table_id(),
                                     table_name(),
                                     metadata_match(),
                                     metadata_write(),
                                     max_entries(),
                                     table_feature_properties()
                                    }.

-type table_features()           :: [table_feature()].

-type packet_in_reason()         :: no_match
                                  | action
                                  | invalid_ttl.
-type packet_in_reasons()        :: [packet_in_reason()].

-type port_status_reason()       :: add
                                  | delete
                                  | modify.
-type port_status_reasons()      :: [port_status_reason()].

-type flow_removed_reason()      :: idle_timeout
                                  | hard_timeout
                                  | delete
                                  | group_delete.
-type flow_removed_reasons()      :: [flow_removed_reason()].

-type packet_in_mask()            :: {packet_in_reasons(),
                                      packet_in_reasons()}.
-type port_status_mask()          :: {port_status_reasons(),
                                      port_status_reasons()}.
-type flow_removed_mask()         :: {flow_removed_reasons(),
                                      flow_removed_reasons()}.

-type xid()                       :: non_neg_integer().

%%%===================================================================
%%% API
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc
%% Decode a message.
%% @end
%%--------------------------------------------------------------------
-spec decode(ofp_message()) -> {atom(), xid(), proplists:proplist()}.
decode(#ofp_message{ version = ?V4, xid = Xid, body = Body }) ->
    {Name, Res} = of_msg_lib_v4:decode(Body),
    {Name, Xid, Res};
decode(#ofp_message{ version = Version, xid = Xid, body = Body })
                                                    when Version < 4 ->
    % decode first looks for protocol versions it knows about, older
    % unsupported versions end up here.  The only unsupported versions
    % of OF we should get are the handshake hello messages.
    {Name, Res} = decode_hello(Body),
    {Name, Xid, Res};
decode(#ofp_message{ xid = Xid, body = Body }) ->
    % newer unsupported versions of OF protocol.  Assume that
    % the newest version of our OF parser can decode the hello message.
    {Name, Res} = of_msg_lib_v4:decode(Body),
    {Name, Xid, Res}.

%%--------------------------------------------------------------------
%% @doc
%% Create error
%% @end
%%--------------------------------------------------------------------
-spec create_error(version(), atom(), atom()) -> ofp_message().
create_error(?V4, Type, Code) ->
    #ofp_message{ version = ?V4,
                  body = of_msg_lib_v4:create_error(Type, Code) }.

%%--------------------------------------------------------------------
%% @doc
%% Create hello.
%% @end
%%--------------------------------------------------------------------
-spec hello(version(), supported_versions()) -> ofp_message().
hello(?V4, SupportedVersions) ->
    #ofp_message{ version = ?V4,
                  body = of_msg_lib_v4:hello(SupportedVersions) }.

%%--------------------------------------------------------------------
%% @doc
%% Create an echo request.
%% @end
%%--------------------------------------------------------------------
-spec echo_request(version(), binary()) -> ofp_message().
echo_request(?V4, Data) ->
    #ofp_message{ version = ?V4,
                  body = of_msg_lib_v4:echo_request(Data) }.

%%--------------------------------------------------------------------
%% @doc
%% Create a features request.
%% @end
%%--------------------------------------------------------------------
-spec get_features(version()) -> ofp_message().
get_features(?V4) ->
    #ofp_message{ version = ?V4,
                  body = of_msg_lib_v4:get_features() }.

%%--------------------------------------------------------------------
%% @doc
%% Create a get_config request.
%% @end
%%--------------------------------------------------------------------
-spec get_config(version()) -> ofp_message().
get_config(?V4) ->
    #ofp_message{ version = ?V4,
                  body = of_msg_lib_v4:get_config() }.

%%--------------------------------------------------------------------
%% @doc
%% Create a set_config request.
%% @end
%%--------------------------------------------------------------------
-spec set_config(version(), config_flags(), miss_send_len()) -> ofp_message().
set_config(?V4, Flags, PacketInBytes) ->
    #ofp_message{ version = ?V4,
                  body = of_msg_lib_v4:set_config(Flags, PacketInBytes) }.

%%--------------------------------------------------------------------
%% @doc
%% Create a packet_out request. Data is either a bufferId or a binary packet.
%% @end
%%--------------------------------------------------------------------
-spec send_packet(version(), non_neg_integer()|binary(), port_no(), actions()) -> ofp_message().
send_packet(?V4, Data, InPort, Actions) ->
    #ofp_message{ version = ?V4,
                  body = of_msg_lib_v4:send_packet(Data, InPort, Actions) }.

%%--------------------------------------------------------------------
%% @doc
%% Create a request to add a flow.
%% @end
%%--------------------------------------------------------------------
-spec flow_add(version(), matches(), instructions(), opts()) -> ofp_message().
flow_add(?V4, Matches, Instructions, Opts) ->
    #ofp_message{ version = ?V4,
                  body = of_msg_lib_v4:flow_add(Matches, Instructions, Opts) }.

%%--------------------------------------------------------------------
%% @doc
%% Create a request  to modify one or more flows.
%% @end
%%--------------------------------------------------------------------
-spec flow_modify(version(), matches(), instructions(), opts()) -> ofp_message().
flow_modify(?V4, Matches, Instructions, Opts) ->
    #ofp_message{ version = ?V4,
                  body = of_msg_lib_v4:flow_modify(Matches, Instructions, Opts) }.

%%--------------------------------------------------------------------
%% @doc
%% Create a request to delete one or more flows.
%% @end
%%--------------------------------------------------------------------
-spec flow_delete(version(), matches(), opts()) -> ofp_message().
flow_delete(?V4, Matches, Opts) ->
    #ofp_message{ version = ?V4,
                  body = of_msg_lib_v4:flow_delete(Matches, Opts) }.

%%--------------------------------------------------------------------
%% @doc
%% Create a request to add a group.
%% @end
%%--------------------------------------------------------------------
-spec group_add(version(), group_type(), group_id(), buckets()) -> ofp_message().
group_add(?V4, Type, Id, Buckets) ->
    #ofp_message{ version = ?V4,
                  body = of_msg_lib_v4:group_add(Type, Id, Buckets) }.

%%--------------------------------------------------------------------
%% @doc
%% Create a request to modify a group.
%% @end
%%--------------------------------------------------------------------
-spec group_modify(version(), group_type(), group_id(), buckets()) -> ofp_message().
group_modify(?V4, Type, Id, Buckets) ->
    #ofp_message{ version = ?V4,
                  body = of_msg_lib_v4:group_modify(Type, Id, Buckets) }.

%%--------------------------------------------------------------------
%% @doc
%% Create a request to delete a group.
%% @end
%%--------------------------------------------------------------------
-spec group_delete(version(), group_type(), group_id()) -> ofp_message().
group_delete(?V4, Type, Id) ->
    #ofp_message{ version = ?V4,
                  body = of_msg_lib_v4:group_delete(Type, Id) }.

%%--------------------------------------------------------------------
%% @doc
%% Create a request to change the administrative state of a port to UP.
%% @end
%%--------------------------------------------------------------------
-spec set_port_up(version(), mac_addr(), port_no()) -> ofp_message().
set_port_up(?V4, Addr, PortNo) ->
    #ofp_message{ version = ?V4,
                  body = of_msg_lib_v4:set_port_up(Addr, PortNo) }.

%%--------------------------------------------------------------------
%% @doc
%% Create a request to change the administrative state of a port to DOWN.
%% @end
%%--------------------------------------------------------------------
-spec set_port_down(version(), mac_addr(), port_no()) -> ofp_message().
set_port_down(?V4, Addr, PortNo) ->
    #ofp_message{ version = ?V4,
                  body = of_msg_lib_v4:set_port_down(Addr, PortNo) }.

%%--------------------------------------------------------------------
%% @doc
%% Create a request to set a port to accept incoming packets.
%% @end
%%--------------------------------------------------------------------
-spec set_port_recv(version(), mac_addr(), port_no()) -> ofp_message().
set_port_recv(?V4, Addr, PortNo) ->
    #ofp_message{ version = ?V4,
                  body = of_msg_lib_v4:set_port_recv(Addr, PortNo) }.

%%--------------------------------------------------------------------
%% @doc
%% Create a request to set a port to NOT accept incoming packets.
%% @end
%%--------------------------------------------------------------------
-spec set_port_no_recv(version(), mac_addr(), port_no()) -> ofp_message().
set_port_no_recv(?V4, Addr, PortNo) ->
    #ofp_message{ version = ?V4,
                  body = of_msg_lib_v4:set_port_no_recv(Addr, PortNo) }.

%%--------------------------------------------------------------------
%% @doc
%% Create a request to set a port to allow sending outgoing packets
%% @end
%%--------------------------------------------------------------------
-spec set_port_fwd(version(), mac_addr(), port_no()) -> ofp_message().
set_port_fwd(?V4, Addr, PortNo) ->
    #ofp_message{ version = ?V4,
                  body = of_msg_lib_v4:set_port_fwd(Addr, PortNo) }.

%%--------------------------------------------------------------------
%% @doc
%% Create a request to set a port to disallow sending outgoing packets.
%% @end
%%--------------------------------------------------------------------
-spec set_port_no_fwd(version(), mac_addr(), port_no()) -> ofp_message().
set_port_no_fwd(?V4, Addr, PortNo) ->
    #ofp_message{ version = ?V4,
                  body = of_msg_lib_v4:set_port_no_fwd(Addr, PortNo) }.

%%--------------------------------------------------------------------
%% @doc
%% Create a request to set a port to send packet_in messages in case of
%% a table miss.
%% @end
%%--------------------------------------------------------------------
-spec set_port_packet_in(version(), mac_addr(), port_no()) -> ofp_message().
set_port_packet_in(?V4, Addr, PortNo) ->
    #ofp_message{ version = ?V4,
                  body = of_msg_lib_v4:set_port_packet_in(Addr, PortNo) }.

%%--------------------------------------------------------------------
%% @doc
%% Create a request to set a port to NOT send packet_in messages in
%% case of a table miss.
%% @end
%%--------------------------------------------------------------------
-spec set_port_no_packet_in(version(), mac_addr(), port_no()) -> ofp_message().
set_port_no_packet_in(?V4, Addr, PortNo) ->
    #ofp_message{ version = ?V4,
                  body = of_msg_lib_v4:set_port_no_packet_in(Addr, PortNo) }.

%%--------------------------------------------------------------------
%% @doc
%% Create a request to get information about the switch manufacturer,
%% hardware revision, software revision, serial number, and a description.
%% @end
%%--------------------------------------------------------------------
-spec get_description(version()) -> ofp_message().
get_description(?V4) ->
    #ofp_message{ version = ?V4,
                  body = of_msg_lib_v4:get_description() }.

%%--------------------------------------------------------------------
%% @doc
%% Create a request to get flow statistics.
%% @end
%%--------------------------------------------------------------------
-spec get_flow_statistsics(version(), table_id(), matches(), opts()) -> ofp_message().
get_flow_statistsics(?V4, TableId, Matches, Opts) ->
    #ofp_message{ version = ?V4,
                  body = of_msg_lib_v4:get_flow_statistsics(TableId, Matches, Opts) }.

%%--------------------------------------------------------------------
%% @doc
%% Create a request to get aggregate flow statistics.
%% @end
%%--------------------------------------------------------------------
-spec get_aggregate_statistics(version(), table_id(), matches(), opts()) -> ofp_message().
get_aggregate_statistics(?V4, TableId, Matches, Opts) ->
    #ofp_message{ version = ?V4,
                  body = of_msg_lib_v4:get_aggregate_statistics(TableId, Matches, Opts) }.

%%--------------------------------------------------------------------
%% @doc
%% Create a request to get table statistics.
%% @end
%%--------------------------------------------------------------------
-spec get_table_stats(version()) -> ofp_message().
get_table_stats(?V4) ->
    #ofp_message{ version = ?V4,
                  body = of_msg_lib_v4:get_table_stats() }.

%%--------------------------------------------------------------------
%% @doc
%% Create a request to get table features.
%% @end
%%--------------------------------------------------------------------
-spec get_table_features(version()) -> ofp_message().
get_table_features(?V4) ->
    #ofp_message{ version = ?V4,
                  body = of_msg_lib_v4:get_table_features() }.

%%--------------------------------------------------------------------
%% @doc
%% Create a request to set table features.
%% @end
%%--------------------------------------------------------------------
-spec set_table_features(version(), table_features()) -> ofp_message().
set_table_features(?V4, Features) ->
    #ofp_message{ version = ?V4,
                  body = of_msg_lib_v4:set_table_features(Features) }.

%%--------------------------------------------------------------------
%% @doc
%% Create a request to get port descriptions.
%% @end
%%--------------------------------------------------------------------
-spec get_port_descriptions(version()) -> ofp_message().
get_port_descriptions(?V4) ->
    #ofp_message{ version = ?V4,
                  body = of_msg_lib_v4:get_port_descriptions() }.

%%--------------------------------------------------------------------
%% @doc
%% Create a request to get port statistics.
%% @end
%%--------------------------------------------------------------------
-spec get_port_statistics(version(), port_no()) -> ofp_message().
get_port_statistics(?V4, Port) ->
    #ofp_message{ version = ?V4,
                  body = of_msg_lib_v4:get_port_statistics(Port) }.

%%--------------------------------------------------------------------
%% @doc
%% Create a request to get queue statistics.
%% @end
%%--------------------------------------------------------------------
-spec get_queue_statistics(version(), port_no(), queue_id()) -> ofp_message().
get_queue_statistics(?V4, PortNo, QueueId) ->
    #ofp_message{ version = ?V4,
                  body = of_msg_lib_v4:get_queue_statistics(PortNo, QueueId) }.

%%--------------------------------------------------------------------
%% @doc
%% Create a request to get group statistics.
%% @end
%%--------------------------------------------------------------------
-spec get_group_statistics(version(), group_id()) -> ofp_message().
get_group_statistics(?V4, GroupId) ->
    #ofp_message{ version = ?V4,
                  body = of_msg_lib_v4:get_group_statistics(GroupId) }.

%%--------------------------------------------------------------------
%% @doc
%% Create a request to get group descriptions.
%% @end
%%--------------------------------------------------------------------
-spec get_group_descriptions(version()) -> ofp_message().
get_group_descriptions(?V4) ->
    #ofp_message{ version = ?V4,
                  body = of_msg_lib_v4:get_group_descriptions() }.

%%--------------------------------------------------------------------
%% @doc
%% Create a request to get group features.
%% @end
%%--------------------------------------------------------------------
-spec get_group_features(version()) -> ofp_message().
get_group_features(?V4) ->
    #ofp_message{ version = ?V4,
                  body = of_msg_lib_v4:get_group_features() }.

%%--------------------------------------------------------------------
%% @doc
%% Create a request to get meter statistics.
%% @end
%%--------------------------------------------------------------------
-spec get_meter_stats(version(), meter_id()) -> ofp_message().
get_meter_stats(?V4, MeterId) ->
    #ofp_message{ version = ?V4,
                  body = of_msg_lib_v4:get_meter_stats(MeterId) }.

%%--------------------------------------------------------------------
%% @doc
%% Create a request to get meter configuration.
%% @end
%%--------------------------------------------------------------------
-spec get_meter_configuration(version(), meter_id()) -> ofp_message().
get_meter_configuration(?V4, MeterId) ->
    #ofp_message{ version = ?V4,
                  body = of_msg_lib_v4:get_meter_configuration(MeterId) }.

%%--------------------------------------------------------------------
%% @doc
%% Create a request to get meter features.
%% @end
%%--------------------------------------------------------------------
-spec get_meter_features(version()) -> ofp_message().
get_meter_features(?V4) ->
    #ofp_message{ version = ?V4,
                  body = of_msg_lib_v4:get_meter_features() }.

%%--------------------------------------------------------------------
%% @doc
%% Create an experimenter request.
%% @end
%%--------------------------------------------------------------------
-spec experimenter(version(), experimenter_id(), exp_type(), binary()) -> ofp_message().
experimenter(?V4, ExpId, Type, Data) ->
    #ofp_message{ version = ?V4,
                  body = of_msg_lib_v4:experimenter(ExpId, Type, Data) }.

%%--------------------------------------------------------------------
%% @doc
%% Create a barrier request.
%% @end
%%--------------------------------------------------------------------
-spec barrier(version()) -> ofp_message().
barrier(?V4) ->
    #ofp_message{ version = ?V4,
                  body = of_msg_lib_v4:barrier() }.

%%--------------------------------------------------------------------
%% @doc
%% Create a request to get queue configuration.
%% @end
%%--------------------------------------------------------------------
-spec get_queue_configuration(version(), port_no()) -> ofp_message().
get_queue_configuration(?V4, PortNo) ->
    #ofp_message{ version = ?V4,
                  body = of_msg_lib_v4:get_queue_configuration(PortNo) }.

%%--------------------------------------------------------------------
%% @doc
%% Create a request to change the role of the controller.
%% @end
%%--------------------------------------------------------------------
-spec set_role(version(), role(), generation_id()) -> ofp_message().
set_role(?V4, Role, GenerationId) ->
    #ofp_message{ version = ?V4,
                  body = of_msg_lib_v4:set_role(Role, GenerationId) }.

%%--------------------------------------------------------------------
%% @doc
%% Create a request to get the configuration for subscription of
%% asynchronous messages.
%% @end
%%--------------------------------------------------------------------
-spec get_async_configuration(version()) -> ofp_message().
get_async_configuration(?V4) ->
    #ofp_message{ version = ?V4,
                  body = of_msg_lib_v4:get_async_configuration() }.

%%--------------------------------------------------------------------
%% @doc
%% Create a request to change the configuration for subscription of
%% asynchronous messages.
%% @end
%%--------------------------------------------------------------------
-spec set_async_configuration(version(), packet_in_mask(), port_status_mask(), flow_removed_mask()) -> ofp_message().
set_async_configuration(?V4, PacketInMask, PortStatusMask, FlowRemovedMask) ->
    #ofp_message{ version = ?V4,
                  body = of_msg_lib_v4:set_async_configuration(PacketInMask,
                                                               PortStatusMask,
                                                               FlowRemovedMask) }.

%%--------------------------------------------------------------------
%% @doc
%% Create a request to add a meter.
%% @end
%%--------------------------------------------------------------------
-spec meter_add(version(), meter_flags(), meter_id(), bands()) -> ofp_message().
meter_add(?V4, Flags, MeterId, Bands) ->
    #ofp_message{ version = ?V4,
                  body = of_msg_lib_v4:meter_add(Flags, MeterId, Bands) }.

%%--------------------------------------------------------------------
%% @doc
%% Create a request to modify a meter.
%% @end
%%--------------------------------------------------------------------
-spec meter_modify(version(), meter_flags(), meter_id(), bands()) -> ofp_message().
meter_modify(?V4, Flags, MeterId, Bands) ->
    #ofp_message{ version = ?V4,
                  body = of_msg_lib_v4:meter_modify(Flags, MeterId, Bands) }.

%%--------------------------------------------------------------------
%% @doc
%% Create a request to delete a meter.
%% @end
%%--------------------------------------------------------------------
-spec meter_delete(version(), meter_id()) -> ofp_message().
meter_delete(?V4, MeterId) ->
    #ofp_message{ version = ?V4,
                  body = of_msg_lib_v4:meter_delete(MeterId) }.

%%%===================================================================
%%% Internal functions
%%%===================================================================

decode_hello(#ofp_hello{}) ->
    {hello, []}.
