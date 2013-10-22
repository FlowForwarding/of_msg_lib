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

-module(of_msg_lib_v4).

-export([get_features/0,
         get_config/0,
         set_config/2,
         send_packet/3,
         flow_add/3,
         flow_modify/3,
         flow_delete/2,
         group_add/3,
         group_modify/3,
         group_delete/2,
         set_port_up/2,
         set_port_down/2,
         set_port_recv/2,
         set_port_no_recv/2,
         set_port_fwd/2,
         set_port_no_fwd/2,
         set_port_packet_in/2,
         set_port_no_packet_in/2,
         get_description/0,
         get_flow_statistsics/3,
         get_aggregate_statistics/3,
         get_table_stats/0,
         get_table_features/0,
         set_table_features/1,
         get_port_descriptions/0,
         get_port_statistics/1,
         get_queue_statistics/2,
         get_group_statistics/1,
         get_group_descriptions/0,
         get_group_features/0,
         get_meter_stats/1,
         get_meter_configuration/1,
         get_meter_features/0,
         experimenter/3,
         barrier/0,
         get_queue_configuration/1,
         set_role/2,
         get_async_configuration/0,
         set_async_configuration/3,
         meter_add/3,
         meter_modify/3,
         meter_delete/1,
         decode/1]).

-export([in_port/1,
         in_phy_port/1,
         metadata/1, metadata/2,
         eth_dst/1, eth_dst/2,
         eth_src/1, eth_src/2,
         eth_type/1,
         vlan_vid/1, vlan_vid/2,
         vlan_pcp/1,
         ip_dscp/1,
         ip_ecn/1,
         ip_proto/1,
         ipv4_src/1, ipv4_src/2,
         ipv4_dst/1, ipv4_dst/2,
         tcp_src/1,
         tcp_dst/1,
         udp_src/1,
         udp_dst/1,
         sctp_src/1,
         sctp_dst/1,
         icmpv4_type/1,
         icmpv4_code/1,
         arp_op/1,
         arp_spa/1, arp_spa/2,
         arp_tpa/1, arp_tpa/2,
         arp_sha/1, arp_sha/2,
         arp_tha/1, arp_tha/2,
         ipv6_src/1, ipv6_src/2,
         ipv6_dst/1, ipv6_dst/2,
         ipv6_label/1, ipv6_label/2,
         icmpv6_type/1,
         icmpv6_code/1,
         ipv6_nd_target/1,
         ipv6_nd_sll/1,
         ipv6_nd_tll/1,
         mpls_label/1,
         mpls_tc/1,
         mpls_bos/1,
         pbb_isid/1, pbb_isid/2,
         tunnel_id/1, tunnel_id/2,
         ipv6_exthdr/1, ipv6_exthdr/2
        ]).

-include_lib("of_protocol/include/ofp_v4.hrl").

%% Get basic information from the switch. Used at first connection to get
%% DataPathId and capabilities.
get_features() ->
    #ofp_features_request{}.

%% Get configuration of miss_send_len and handling of fragmented packets.
get_config() ->
    #ofp_get_config_request{}.

%% Set configuration of miss_send_len and handling of fragmented packets.
set_config(Flags, PacketInBytes) ->
    #ofp_set_config{
       flags = Flags,
       miss_send_len = PacketInBytes
      }.

%% Send a packet to the switch
send_packet(BufferId, InPort, Actions) when is_integer(BufferId) ->
    #ofp_packet_out{
       buffer_id = BufferId,
       in_port = InPort,
       actions = mk_actions(Actions),
       data = <<>>
      };
send_packet(Data, InPort, Actions) when is_binary(Data) ->
    #ofp_packet_out{
       buffer_id = no_buffer,
       in_port = InPort,
       actions = mk_actions(Actions),
       data = Data
      }.

%% Manage flow tables

flow_add(Matches, Instructions, Opts) ->
    #ofp_flow_mod{
       cookie = get_opt(cookie, Opts, <<0:64>>),
       cookie_mask = get_opt(cookie_mask, Opts, <<0:64>>),
       table_id = get_opt(table_id, Opts, 0),
       command = add,
       idle_timeout = get_opt(idle_timeout, Opts, 0),
       hard_timeout = get_opt(hard_timeout, Opts, 0),
       priority = get_opt(priority, Opts, 16#ffff),
       buffer_id = get_opt(buffer_id, Opts, no_buffer),
       flags = get_opt(flags, Opts, []),
       match = match(mk_matches(Matches)),
       instructions = mk_instructions(Instructions)}.

flow_modify(Matches, Instructions, Opts) ->
    #ofp_flow_mod{
       cookie = get_opt(cookie, Opts, <<0:64>>),
       cookie_mask = get_opt(cookie_mask, Opts, <<0:64>>),
       table_id = get_opt(table_id, Opts, 0),
       command = modify_command(Opts),
       priority = get_opt(priority, Opts, 16#ffff),
       flags = get_opt(flags, Opts, []),
       match = match(mk_matches(Matches)),
       instructions = mk_instructions(Instructions)
      }.

flow_delete(Matches, Opts) ->
    #ofp_flow_mod{
       cookie = get_opt(cookie, Opts, <<0:64>>),
       cookie_mask = get_opt(cookie_mask, Opts, <<0:64>>),
       table_id = get_opt(table_id, Opts, 0),
       command = delete_command(Opts),
       priority = get_opt(priority, Opts, 16#ffff),
       out_port = get_opt(out_port, Opts, any),
       out_group = get_opt(out_group, Opts, any),
       flags = get_opt(flags, Opts, []),
       match = match(mk_matches(Matches))
      }.

%% group admin
group_add(Type, Id, Buckets) ->
    #ofp_group_mod{
       command = add,
       type = Type,
       group_id = Id,
       buckets = mk_buckets(Buckets)
      }.

group_modify(Type, Id, Buckets) ->
    #ofp_group_mod{
       command = modify,
       type = Type,
       group_id = Id,
       buckets = mk_buckets(Buckets)
      }.

group_delete(Type, Id) ->
    #ofp_group_mod{
       command = delete,
       type = Type,        %% Is this really needed for delete
       group_id = Id,
       buckets = []
      }.

%% port admin
%%% Administrative State
%% up/down
set_port_up(Addr, PortNo) ->
    #ofp_port_mod{
       port_no = PortNo,
       hw_addr = Addr,
       config = [],
       mask = [port_down],
       advertise = []
      }.

set_port_down(Addr, PortNo) ->
    #ofp_port_mod{
       port_no = PortNo,
       hw_addr = Addr,
       config = [port_down],
       mask = [port_down],
       advertise = []
      }.

set_port_recv(Addr, PortNo) ->
    #ofp_port_mod{
       port_no = PortNo,
       hw_addr = Addr,
       config = [],
       mask = [no_recv],
       advertise = []
      }.

set_port_no_recv(Addr, PortNo) ->
    #ofp_port_mod{
       port_no = PortNo,
       hw_addr = Addr,
       config = [no_recv],
       mask = [no_recv],
       advertise = []
      }.

set_port_fwd(Addr, PortNo) ->
    #ofp_port_mod{
       port_no = PortNo,
       hw_addr = Addr,
       config = [],
       mask = [no_fwd],
       advertise = []
      }.

set_port_no_fwd(Addr, PortNo) ->
    #ofp_port_mod{
       port_no = PortNo,
       hw_addr = Addr,
       config = [no_fwd],
       mask = [no_fwd],
       advertise = []
      }.

set_port_packet_in(Addr, PortNo) ->
    #ofp_port_mod{
       port_no = PortNo,
       hw_addr = Addr,
       config = [],
       mask = [no_packet_in],
       advertise = []
      }.

set_port_no_packet_in(Addr, PortNo) ->
    #ofp_port_mod{
       port_no = PortNo,
       hw_addr = Addr,
       config = [no_packet_in],
       mask = [no_packet_in],
       advertise = []
      }.

%% %%% Advertised features
%% #ofp_port_mod{}

%% ofp_table_mod
%% Not used in 1.3

%% ofp_desc_request
%% Get general description of the switch, e.g. manufacturer, hardware and
%% software revisionss, serial number
get_description() ->
    #ofp_desc_request{}.

%% ofp_flow_stats_request
%% Get flow statistics from one or all flow tables.
get_flow_statistsics(TableId, Matches, Opts) ->
    #ofp_flow_stats_request{
       table_id = TableId,
       out_port = get_opt(out_port, Opts, any),
       out_group = get_opt(out_group, Opts, any),
       cookie = get_opt(cookie, Opts, <<0:64>>),
       cookie_mask = get_opt(cookie_mask, Opts, <<0:64>>),
       match = match(mk_matches(Matches))
      }.

%% ofp_aggregate_stats_request
%% Get aggregate statistics, (packets, bytes, and flows) for a number of flows matching the filter.
get_aggregate_statistics(TableId, Matches, Opts) ->
    #ofp_aggregate_stats_request{
       table_id = TableId,
       out_port = get_opt(out_port, Opts, any),
       out_group = get_opt(out_group, Opts, any),
       cookie = get_opt(cookie, Opts, <<0:64>>),
       cookie_mask = get_opt(cookie_mask, Opts, <<0:64>>),
       match = match(mk_matches(Matches))
      }.

%% ofp_table_stats_request
%% Get individual flow table statistics, flows, lookups, and hits), for all flow tables.
get_table_stats() ->
    #ofp_table_stats_request{}.

%% ofp_table_features_request
%%% Get
get_table_features() ->
    #ofp_table_features_request{}.
%%% Modify
set_table_features(Features) when is_list(Features) ->
    %% TODO: Features format definition
    #ofp_table_features_request{
       body = Features
      }.

%% ofp_port_desc_request
%% Get description of all ports in the switch
get_port_descriptions() ->
    #ofp_port_desc_request{}.

%% ofp_port_stats_request
%% Get port statistics for one or all ports
get_port_statistics(Port) ->
    #ofp_port_stats_request{
       port_no = Port
      }.

%% ofp_queue_stats_request
%% Get queue statistics for queue or port
get_queue_statistics(PortNo, QueueId) ->
    #ofp_queue_stats_request{
       port_no = PortNo,
       queue_id = QueueId
      }.

%% ofp_group_stats_request
%% Get group statistics for one or all groups.
get_group_statistics(GroupId) ->
    #ofp_group_stats_request{
       group_id = GroupId
      }.

%% ofp_group_desc_request
%% Get group descriptions for all groups
get_group_descriptions() ->
    #ofp_group_desc_request{}.

%% ofp_group_features_request
%% Get the group capabilities supported by the switch
get_group_features() ->
    #ofp_group_features_request{}.

%% ofp_meter_stats_request
%% Get meter statistics for one or all meters.
get_meter_stats(MeterId) ->
    #ofp_meter_stats_request{
       meter_id = MeterId
      }.

%% ofp_meter_config_request
%% Get meter configuration fo rone or all meters
get_meter_configuration(MeterId) ->
    #ofp_meter_config_request{
       meter_id = MeterId
      }.

%% ofp_meter_features_request
%% Get meter features supported by the switch
get_meter_features() ->
    #ofp_meter_features_request{}.

%% ofp_experimenter_request
experimenter(ExpId, Type, Data) ->
    #ofp_experimenter_request{
       experimenter = ExpId,
       exp_type = Type,
       data = Data
      }.

%% barrier_request
%% Send a barrier request.
barrier() ->
    #ofp_barrier_request{}.

%% queue_get_config
%% Get Queue confirguration for one or all ports
get_queue_configuration(Port) ->
    #ofp_queue_get_config_request{
       port = Port
      }.

%% ofp_role_request
%% Send role request
set_role(Role, GenerationId) ->
    #ofp_role_request{
       role = Role,
       generation_id = GenerationId
      }.

%% get_subscribed_events
%% Get the configuration of asynchronous messages
get_async_configuration() ->
    #ofp_get_async_request{}.

%% set_subscribed_events

%% Set the configuration of asynchronous messages
set_async_configuration(PacketInMask, PortStatusMask, FlowRemovedMask) ->
    #ofp_set_async{
       packet_in_mask = PacketInMask,
       port_status_mask = PortStatusMask,
       flow_removed_mask = FlowRemovedMask
      }.

%% ofp_meter_mod
%%% meter_add
meter_add(Flags, MeterId, Bands) ->
    #ofp_meter_mod{
       command = add,
       flags = Flags,
       meter_id = MeterId,
       bands = mk_bands(Bands)
      }.
%%% meter_modify
meter_modify(Flags, MeterId, Bands) ->
    #ofp_meter_mod{
       command = modify,
       flags = Flags,
       meter_id = MeterId,
       bands = mk_bands(Bands)
      }.
%%% meter_delete
meter_delete(MeterId) ->
    #ofp_meter_mod{
       command = delete,
       flags = [],
       meter_id = MeterId,
       bands = []
      }.

%% Asynchronous Events
%%% Packet In
%% Receive a packet from the switch.
%%% Flow Removed
%% Receive notification that a flow has been removed in the switch
%%% Port Status
%% Receive notification that a port has changed state


%%% ===================================================================
modify_command(Opts) ->
    case get_opt(strict, Opts, false) of
        false ->
            modify;
        true ->
            modify_strict
    end.

delete_command(Opts) ->
    case get_opt(strict, Opts, false) of
        false ->
            delete;
        true ->
            delete_strict
    end.

get_opt(Opt, Opts, Default) ->
    proplists:get_value(Opt, Opts, Default).

%%============================================================================
%% Matching
%% Create match specifications, checking that prerequisite fields are present
%% and if not adding them.

mk_matches(Ms) ->
    mk_matches(Ms,[]).

mk_matches([M|Ms], Acc) ->
    mk_matches(Ms, mk_match(M,Acc));
mk_matches([], Acc) ->
    lists:reverse(Acc).

mk_match({Field,Val}, Acc) ->
    Acc1 = add_required_fields(Field, Acc),
    [?MODULE:Field(Val)|Acc1];
mk_match({Field,Val,Mask}, Acc) ->
    [?MODULE:Field(Val,Mask)|Acc].

add_required_fields(Field, Acc) ->
    case required(Field) of
	{F,V} ->
	    case has_match(F,V,Acc) of
		missing ->
		    [?MODULE:F(V)|add_required_fields(F, Acc)];
		present ->
		    Acc
	    end;
	[{F1,V1},{F2,V2}]=M ->
	    case (has_match(F1,V1,Acc)==present) or (has_match(F2,V2,Acc)==present) of
		true ->
		    Acc;
		false ->
		    throw({missing_match,M})
	    end;
	none ->
	    Acc
    end.


has_match(Field, Val, Acc) ->
    case lists:keyfind(Field, #ofp_field.name, Acc) of
	#ofp_field{value=Val} ->
	    present;
	#ofp_field{} ->
	    other;
	false ->
	    missing
    end.

required(in_phy_port) ->
    in_port;
required(vlan_pcp) ->
    %% this needs work
    {vlan_vid,none};
required(ip_dscp) ->
    [{eth_type,16#800},{eth_type,16#86dd}];
required(ip_ecn) ->
    [{eth_type,16#800},{eth_type,16#86dd}];
required(ip_proto) ->
    [{eth_type,<<16#800:16>>},{eth_type,<<16#86dd:16>>}];
required(ipv4_src) ->
    {eth_type,16#800};
required(ipv4_dst) ->
    {eth_type,16#800};
required(tcp_src) ->
    {ip_proto,6};
required(tcp_dst) ->
    {ip_proto,6};
required(udp_src) ->
    {ip_proto,17};
required(udp_dst) ->
    {ip_proto,17};
required(sctp_src) ->
    {ip_proto,132};
required(sctp_dst) ->
    {ip_proto,132};
required(icmpv4_type) ->
    {ip_proto,1};
required(icmpv4_code) ->
    {ip_proto,1};
required(arp_op) ->
    {eth_type,16#806};
required(arp_spa) ->
    {eth_type,16#806};
required(arp_tpa) ->
    {eth_type,16#806};
required(arp_sha) ->
    {eth_type,16#806};
required(arp_tha) ->
    {eth_type,16#806};
required(ipv6_src) ->
    {eth_type,16#86dd};
required(ipv6_dst) ->
    {eth_type,16#86dd};
required(ipv6_flabel) ->
    {eth_type,16#86dd};
required(icmpv6_type) ->
    {ip_proto,58};
required(icmpv6_code) ->
    {ip_proto,58};
required(ipv6_nd_target) ->
    [{icmpv6_type,135},{icmpv6_type,136}];
required(ipv6_nd_sll) ->
    {icmpv6_type,135};
required(ipv6_nd_tll) ->
    {icmpv6_type,136};
required(mpls_label) ->
    [{eth_type,16#8847},{eth_type,16#8848}];
required(mpls_tc) ->
    [{eth_type,16#8847},{eth_type,16#8848}];
required(mpls_bos) ->
    [{eth_type,16#8847},{eth_type,16#8848}];
required(pbb_isid) ->
    {eth_type,16#88E7};
required(ipv6_exthdr) ->
    {eth_type,16#86dd};
required(_) ->
    none.

%%===========================================================================
%% Matches

match(Fields) when is_list(Fields) ->
    #ofp_match{fields=Fields};
match(Field) ->
    #ofp_match{fields=[Field]}.

%% Fields
in_port(Val) when is_integer(Val) ->
    in_port(<<Val:32>>);
in_port(Val) when byte_size(Val) == 4 ->
    #ofp_field{name = in_port,
	       value = Val}.

in_phy_port(Val) when is_integer(Val) ->
    in_phy_port(<<Val:32>>);
in_phy_port(Val) when byte_size(Val) == 4 ->
    #ofp_field{name = phy_port,
               value = Val}.

metadata(Val) when byte_size(Val) == 8 ->
    #ofp_field{name = metadata,
               value = Val}.
metadata(Val, Mask) when byte_size(Val) == 8, byte_size(Mask) == 8  ->
    #ofp_field{name = metadata,
               value = Val,
               has_mask = true,
               mask = Mask}.

eth_dst({M1,M2,M3,M4,M5,M6}) ->
    eth_dst(<<M1,M2,M3,M4,M5,M6>>);
eth_dst(Val) when byte_size(Val) == 6 ->
    #ofp_field{name = eth_dst,
               value = Val}.
eth_dst(Val, Mask) when byte_size(Val) == 6, byte_size(Mask) == 6 ->
    #ofp_field{name = eth_dst,
               value = Val,
               has_mask = true,
               mask = Mask}.

eth_src({M1,M2,M3,M4,M5,M6}) ->
    eth_src(<<M1,M2,M3,M4,M5,M6>>);
eth_src(Val) when byte_size(Val) == 6 ->
    #ofp_field{name = eth_src,
               value = Val}.
eth_src(Val, Mask) when byte_size(Val) == 6, byte_size(Mask) == 6 ->
    #ofp_field{name = eth_src,
               value = Val,
               has_mask = true,
               mask = Mask}.

eth_type(Val) when is_integer(Val) ->
    eth_type(<<Val:16>>);
eth_type(Val) when byte_size(Val) == 2 ->
    #ofp_field{name = eth_type,
               value = Val}.

vlan_vid(Val) when is_integer(Val) ->
    vlan_vid(<<Val:13>>);
vlan_vid(Val) ->
    #ofp_field{name = vlan_vid,
               value = <<Val:13>>}.
vlan_vid(Val, Mask) when is_integer(Val), is_integer(Mask) ->
    vlan_vid(<<Val:13>>, <<Mask:13>>);
vlan_vid(Val, Mask) ->
    #ofp_field{name = vlan_vid,
               value = Val,
               has_mask = true,
               mask = Mask}.

vlan_pcp(Val) when byte_size(Val) == 3 ->
    #ofp_field{name = vlan_pcp,
               value = Val}.

ip_dscp(Val) when byte_size(Val) == 6 ->
    #ofp_field{name = ip_dscp,
               value = Val}.

ip_ecn(Val) when byte_size(Val) == 2 ->
    #ofp_field{name = ip_ecn,
               value = Val}.

ip_proto(Val) when byte_size(Val) == 8 ->
    #ofp_field{name = ip_proto,
               value = Val}.

ipv4_src(Val) when byte_size(Val) == 4 ->
    #ofp_field{name = ipv4_src,
               value = Val}.
ipv4_src(Val, Mask) when byte_size(Val) == 4, byte_size(Mask) == 4 ->
    #ofp_field{name = ipv4_src,
               value = Val,
               has_mask = true,
               mask = Mask}.

ipv4_dst(Val) when byte_size(Val) == 4 ->
    #ofp_field{name = ipv4_dst,
               value = Val}.
ipv4_dst(Val, Mask) when byte_size(Val) == 4, byte_size(Mask) == 4 ->
    #ofp_field{name = ipv4_dst,
               value = Val,
               has_mask = true,
               mask = Mask}.

tcp_src(Val) when byte_size(Val) == 2 ->
    #ofp_field{name = tcp_src,
               value = Val}.

tcp_dst(Val) when byte_size(Val) == 2 ->
    #ofp_field{name = tcp_dst,
               value = Val}.

udp_src(Val) when byte_size(Val) == 2 ->
    #ofp_field{name = udp_src,
               value = Val}.

udp_dst(Val) when byte_size(Val) == 2 ->
    #ofp_field{name = udp_dst,
               value = Val}.

sctp_src(Val) when byte_size(Val) == 2 ->
    #ofp_field{name = sctp_src,
               value = Val}.

sctp_dst(Val) when byte_size(Val) == 2 ->
    #ofp_field{name = sctp_dst,
               value = Val}.

icmpv4_type(Val) when byte_size(Val) == 1 ->
    #ofp_field{name = icmpv4_type,
               value = Val}.

icmpv4_code(Val) when byte_size(Val) == 1 ->
    #ofp_field{name = icmpv4_code,
               value = Val}.

arp_op(Val) when byte_size(Val) == 2 ->
    #ofp_field{name = arp_op,
               value = Val}.

arp_spa(Val) when byte_size(Val) == 4 ->
    #ofp_field{name = arp_spa,
               value = Val}.

arp_spa(Val, Mask) when byte_size(Val) == 4, byte_size(Mask) == 4->
    #ofp_field{name = arp_spa,
               value = Val,
               has_mask = true,
               mask = Mask}.

arp_tpa(Val) when byte_size(Val) == 4 ->
    #ofp_field{name = arp_tpa,
               value = Val}.
arp_tpa(Val, Mask) when byte_size(Val) == 4, byte_size(Mask) == 4->
    #ofp_field{name = arp_tpa,
               value = Val,
               has_mask = true,
               mask = Mask}.

arp_sha(Val) when byte_size(Val) == 6 ->
    #ofp_field{name = arp_sha,
               value = Val}.
arp_sha(Val, Mask) when byte_size(Val) == 6, byte_size(Mask) == 6->
    #ofp_field{name = arp_sha,
               value = Val,
               has_mask = true,
               mask = Mask}.

arp_tha(Val) when byte_size(Val) == 6 ->
    #ofp_field{name = arp_tha,
               value = Val}.
arp_tha(Val, Mask) when byte_size(Val) == 6, byte_size(Mask) == 6->
    #ofp_field{name = arp_tha,
               value = Val,
               has_mask = true,
               mask = Mask}.

ipv6_src(Val) when byte_size(Val) == 16 ->
    #ofp_field{name = ipv6_src,
               value = Val}.
ipv6_src(Val, Mask) when byte_size(Val) == 16, byte_size(Mask) == 16->
    #ofp_field{name = ipv6_src,
               value = Val,
               has_mask = true,
               mask = Mask}.

ipv6_dst(Val) when byte_size(Val) == 16 ->
    #ofp_field{name = ipv6_dst,
               value = Val}.
ipv6_dst(Val, Mask) when byte_size(Val) == 16, byte_size(Mask) == 16->
    #ofp_field{name = ipv6_dst,
               value = Val,
               has_mask = true,
               mask = Mask}.

ipv6_label(Val) when bit_size(Val) == 20 ->
    #ofp_field{name = ipv6_label,
               value = Val}.
ipv6_label(Val, Mask) when byte_size(Val) == 20, byte_size(Mask) == 20->
    #ofp_field{name = ipv6_label,
               value = Val,
               has_mask = true,
               mask = Mask}.

icmpv6_type(Val) when byte_size(Val) == 1 ->
    #ofp_field{name = icmpv6_type,
               value = Val}.

icmpv6_code(Val) when byte_size(Val) == 1 ->
    #ofp_field{name = icmpv6_code,
               value = Val}.

ipv6_nd_target(Val) when byte_size(Val) == 16 ->
    #ofp_field{name = ipv6_nd_target,
               value = Val}.

ipv6_nd_sll(Val) when byte_size(Val) == 6 ->
    #ofp_field{name = ipv6_nd_sll,
               value = Val}.

ipv6_nd_tll(Val) when byte_size(Val) == 6 ->
    #ofp_field{name = ipv6_nd_tll,
               value = Val}.

mpls_label(Val) when bit_size(Val) == 20 ->
    #ofp_field{name = mpls_label,
               value = Val}.

mpls_tc(Val) when bit_size(Val) == 3 ->
    #ofp_field{name = mpls_tc,
               value = Val}.

mpls_bos(Val) when bit_size(Val) == 1 ->
    #ofp_field{name = mpls_bos,
               value = Val}.

pbb_isid(Val) when byte_size(Val) == 3 ->
    #ofp_field{name = pbb_isid,
               value = Val}.

pbb_isid(Val, Mask) when byte_size(Val) == 3, byte_size(Mask) == 3 ->
    #ofp_field{name = pbb_isid,
               value = Val,
               has_mask = true,
               mask = Mask}.

tunnel_id(Val) when byte_size(Val) == 8 ->
    #ofp_field{name = tunnel_id,
               value = Val}.

tunnel_id(Val, Mask) when byte_size(Val) == 8, byte_size(Mask) == 8 ->
    #ofp_field{name = tunnel_id,
               value = Val,
               has_mask = true,
               mask = Mask}.

ipv6_exthdr(Val) when bit_size(Val) == 9 ->
    #ofp_field{name = ipv6_exthdr,
               value = Val}.

ipv6_exthdr(Val, Mask) when bit_size(Val) == 9, bit_size(Mask) == 9 ->
    #ofp_field{name = ipv6_exthdr,
               value = Val,
               has_mask = true,
               mask = Mask}.

%%=============================================================================
                                                %& Instructions
mk_instructions(Is) ->
    [mk_instruction(I) || I<-Is].

mk_instruction({apply_actions, Actions}) when is_list(Actions) ->
    #ofp_instruction_apply_actions{actions=mk_actions(Actions)};

mk_instruction({apply_actions, Action}) ->
    #ofp_instruction_apply_actions{actions=mk_actions([Action])};

mk_instruction(clear_actions) ->
    #ofp_instruction_clear_actions{};

mk_instruction({write_actions, Actions}) when is_list(Actions) ->
    #ofp_instruction_write_actions{actions=mk_actions(Actions)};

mk_instruction({write_actions, Action}) ->
    #ofp_instruction_write_actions{actions=mk_actions([Action])};

mk_instruction({write_metadata, Metadata}) ->
    #ofp_instruction_write_metadata{metadata=Metadata};

mk_instruction({write_metadata, Metadata, Mask}) ->
    #ofp_instruction_write_metadata{metadata=Metadata,
                                    metadata_mask=Mask};

mk_instruction({goto_table, Table}) ->
    #ofp_instruction_goto_table{table_id=Table};

mk_instruction({experimenter_instr, Exp, Data}) ->
    #ofp_instruction_experimenter{experimenter = Exp,
                                  data = Data}.

%%=============================================================================
                                                %& Actions

mk_actions(As) ->
    [mk_action(A) || A<-As].

mk_action({output, Port, MaxLen}) ->
    #ofp_action_output{port = Port,
		       max_len = MaxLen};

mk_action({group, Group}) ->
    #ofp_action_group{group_id = Group};

mk_action({set_queue, Port, Queue}) ->
    #ofp_action_set_queue{port = Port,
                          queue_id = Queue};

mk_action({set_mpls_ttl, TTL}) ->
    #ofp_action_set_mpls_ttl{mpls_ttl = TTL};

mk_action(dec_mpls_ttl) ->
    #ofp_action_dec_mpls_ttl{};

mk_action({set_nw_ttl, TTL}) ->
    #ofp_action_set_nw_ttl{nw_ttl = TTL};

mk_action(dec_nw_ttl) ->
    #ofp_action_dec_nw_ttl{};

mk_action(copy_ttl_out) ->
    #ofp_action_copy_ttl_out{};

mk_action(copy_ttl_in) ->
    #ofp_action_copy_ttl_in{};

mk_action(push_vlan) ->
    #ofp_action_push_vlan{};

mk_action(pop_vlan) ->
    #ofp_action_pop_vlan{};

mk_action({push_mpls, EtherType}) ->
    #ofp_action_push_mpls{ethertype = EtherType};

mk_action({pop_mpls, EtherType}) ->
    #ofp_action_pop_mpls{ethertype = EtherType};

mk_action({set_field, Name, Value}) ->
    #ofp_action_set_field{field = #ofp_field{name=Name,value=Value}};

mk_action({experimenter, Exp, Data}) ->
    #ofp_action_experimenter{experimenter = Exp,
                             data = Data}.

mk_bands(Bands) ->
    [mk_band(B) || B <- Bands].

mk_band({drop, Rate, BurstSize}) ->
    #ofp_meter_band_drop{
       type = drop,
       rate = Rate,
       burst_size = BurstSize};

mk_band({dscp_remark,  Rate, BurstSize, PrecLevel}) ->
    #ofp_meter_band_dscp_remark{
       type = dscp_remark,
       rate = Rate,
       burst_size = BurstSize,
       prec_level = PrecLevel};

mk_band({experimenter,  BandType, Rate, BurstSize, ExperimenterId}) ->
    #ofp_meter_band_experimenter{
       type = experimenter,
       rate = Rate,
       burst_size = BurstSize,
       experimenter = ExperimenterId}.

mk_buckets(Buckets) ->
    [mk_bucket(Bucket) || Bucket <- Buckets].

mk_bucket({Weight, PortNo, GroupId, Actions}) ->
    #ofp_bucket{
       weight = Weight,
       watch_port = PortNo,
       watch_group = GroupId,
       actions = mk_actions(Actions)}.

%%%=========================================================================

decode(#ofp_port{
          port_no = Port_no,
          hw_addr = Hw_addr,
          name = Name,
          config = Config,
          state = State,
          curr = Curr,
          advertised = Advertised,
          supported = Supported,
          peer = Peer,
          curr_speed = Curr_speed,
          max_speed = Max_speed
         }) ->
    [{port_no, Port_no},
     {hw_addr, Hw_addr},
     {name, Name},
     {config, Config},
     {state, State},
     {curr, Curr},
     {advertised, Advertised},
     {supported, Supported},
     {peer, Peer},
     {curr_speed, Curr_speed},
     {max_speed, Max_speed}];

decode(#ofp_queue_prop_min_rate{ rate = Rate }) ->
    [{rate, Rate}];

decode(#ofp_queue_prop_max_rate{ rate = Rate }) ->
    [{rate, Rate}];

decode(#ofp_queue_prop_experimenter{ experimenter = Experimenter, data = Data }) ->
    [{experimenter, Experimenter},
     {data, Data}];

decode(#ofp_packet_queue{
          queue_id = Queue_id,
          port_no = Port_no,
          properties = Properties
         }) ->
    [{queue_id, Queue_id},
     {port_no, Port_no},
     {properties, Properties}];

decode(#ofp_match{ fields = Fields }) ->
    [decode(F) || F <- Fields];

decode(#ofp_field{
          class = openflow_basic,
          name = Name,
          has_mask = false,
          value = Value
         }) ->
    [{Name, Value}];

decode(#ofp_field{
          class = openflow_basic,
          name = Name,
          has_mask = true,
          value = Value,
          mask = Mask
         }) ->
    [{Name, Value, Mask}];

decode(#ofp_instruction_meter{ meter_id = Meter_id }) ->
    [{meter_id, Meter_id}];

decode(#ofp_instruction_apply_actions{ actions = Actions }) ->
    {apply_actions, decode_actions(Actions)};

decode(#ofp_instruction_clear_actions{}) ->
    clear_actions;

decode(#ofp_instruction_write_actions{ actions = Actions }) ->
    [{write_actions, decode_actions(Actions)}];

decode(#ofp_instruction_write_metadata{
          metadata = Metadata,
          metadata_mask = Metadata_mask
         }) ->
    {write_metadata, Metadata, Metadata_mask};

decode(#ofp_instruction_goto_table{ table_id = Table_id }) ->
    {goto_table, Table_id};

decode(#ofp_instruction_experimenter{ experimenter = Experimenter, data = Data }) ->
    {experimenter_instr, Experimenter, Data};

decode(#ofp_action_copy_ttl_in{}) ->
    copy_ttl_in;

decode(#ofp_action_pop_mpls{ ethertype = Ethertype }) ->
    {pop_mpls, Ethertype};

decode(#ofp_action_pop_pbb{}) ->
    pop_pbb;

decode(#ofp_action_pop_vlan{}) ->
    pop_vlan;

decode(#ofp_action_push_mpls{ ethertype = Ethertype }) ->
    {push_mpls, Ethertype};

decode(#ofp_action_push_pbb{ ethertype = Ethertype }) ->
    {push_pbb, Ethertype};

decode(#ofp_action_push_vlan{ ethertype = Ethertype }) ->
    {push_vlan, Ethertype};

decode(#ofp_action_copy_ttl_out{}) ->
    copy_ttl_out;

decode(#ofp_action_dec_mpls_ttl{}) ->
    dec_mpls_ttl;

decode(#ofp_action_dec_nw_ttl{}) ->
    dec_nw_ttl;

decode(#ofp_action_set_mpls_ttl{ mpls_ttl = Mpls_ttl }) ->
    {set_mpls_ttl, Mpls_ttl};

decode(#ofp_action_set_nw_ttl{ nw_ttl = Nw_ttl }) ->
    {set_nw_ttl, Nw_ttl};

decode(#ofp_action_set_field{ field = Field }) ->
    {set_field, Field};

decode(#ofp_action_set_queue{ port = Port, queue_id = Queue_id }) ->
    {set_queue, Port, Queue_id};

decode(#ofp_action_group{ group_id = Group_id }) ->
    {group_id, Group_id};

decode(#ofp_action_output{ port = Port, max_len = Max_len }) ->
    {output, Port, Max_len};

decode(#ofp_action_experimenter{ experimenter = Experimenter, data = Data }) ->
    {experimenter, Experimenter, Data};

decode(#ofp_features_reply{
          datapath_mac = Datapath_mac,
          datapath_id = Datapath_id,
          n_buffers = N_buffers,
          n_tables = N_tables,
          auxiliary_id = Auxiliary_id,
          capabilities = Capabilities
         }) ->
    [{datapath_mac, Datapath_mac},
     {datapath_id, Datapath_id},
     {n_buffers, N_buffers},
     {n_tables, N_tables},
     {auxiliary_id, Auxiliary_id},
     {capabilities, Capabilities}];

decode(#ofp_get_config_reply{ flags = Flags, miss_send_len = Miss_send_len }) ->
    [{flags, Flags},
     {miss_send_len, Miss_send_len}];

decode(#ofp_bucket{
          weight = Weight,
          watch_port = Watch_port,
          watch_group = Watch_group,
          actions = Actions
         }) ->
    [{weight, Weight},
     {watch_port, Watch_port},
     {watch_group, Watch_group},
     {actions, Actions}];

decode(#ofp_meter_band_drop{
          type = Type,
          rate = Rate,
          burst_size = Burst_size
         }) ->
    [{type, Type},
     {rate, Rate},
     {burst_size, Burst_size}];

decode(#ofp_meter_band_dscp_remark{
          type = Type,
          rate = Rate,
          burst_size = Burst_size,
          prec_level = Prec_level
         }) ->
    [{type, Type},
     {rate, Rate},
     {burst_size, Burst_size},
     {prec_level, Prec_level}];

decode(#ofp_meter_band_experimenter{
          type = Type,
          rate = Rate,
          burst_size = Burst_size,
          experimenter = Experimenter
         }) ->
    [{type, Type},
     {rate, Rate},
     {burst_size, Burst_size},
     {experimenter, Experimenter}];

decode(#ofp_desc_reply{
          flags = Flags,
          mfr_desc = Mfr_desc,
          hw_desc = Hw_desc,
          sw_desc = Sw_desc,
          serial_num = Serial_num,
          dp_desc = Dp_desc
         }) ->
    [{flags, Flags},
     {mfr_desc, Mfr_desc},
     {hw_desc, Hw_desc},
     {sw_desc, Sw_desc},
     {serial_num, Serial_num},
     {dp_desc, Dp_desc}];

decode(#ofp_flow_stats{
          table_id = Table_id,
          duration_sec = Duration_sec,
          duration_nsec = Duration_nsec,
          priority = Priority,
          idle_timeout = Idle_timeout,
          hard_timeout = Hard_timeout,
          flags = Flags,
          cookie = Cookie,
          packet_count = Packet_count,
          byte_count = Byte_count,
          match = Match,
          instructions = Instructions
         }) ->
    [{table_id, Table_id},
     {duration_sec, Duration_sec},
     {duration_nsec, Duration_nsec},
     {priority, Priority},
     {idle_timeout, Idle_timeout},
     {hard_timeout, Hard_timeout},
     {flags, Flags},
     {cookie, Cookie},
     {packet_count, Packet_count},
     {byte_count, Byte_count},
     {match, decode_match(Match)},
     {instructions, decode_instructions(Instructions)}];

decode(#ofp_flow_stats_reply{ flags = Flags, body = Body }) ->
    [{flags, Flags},
     {body, [decode(S) || S <- Body]}];

decode(#ofp_aggregate_stats_reply{
          flags = Flags,
          packet_count = Packet_count,
          byte_count = Byte_count,
          flow_count = Flow_count
         }) ->
    [{flags, Flags},
     {packet_count, Packet_count},
     {byte_count, Byte_count},
     {flow_count, Flow_count}];

decode(#ofp_table_stats{
          table_id = Table_id,
          active_count = Active_count,
          lookup_count = Lookup_count,
          matched_count = Matched_count
         }) ->
    [{table_id, Table_id},
     {active_count, Active_count},
     {lookup_count, Lookup_count},
     {matched_count, Matched_count}];

decode(#ofp_table_stats_reply{ flags = Flags, body = Body }) ->
    [{flags, Flags},
     {body, [decode(S) || S <- Body]}];

decode(#ofp_table_feature_prop_instructions{ instruction_ids = Instruction_ids }) ->
    [{instruction_ids, Instruction_ids}];

decode(#ofp_table_feature_prop_instructions_miss{ instruction_ids = Instruction_ids }) ->
    [{instruction_ids, Instruction_ids}];

decode(#ofp_table_feature_prop_next_tables{ next_table_ids = Next_table_ids }) ->
    [{next_table_ids, Next_table_ids}];

decode(#ofp_table_feature_prop_next_tables_miss{ next_table_ids = Next_table_ids }) ->
    [{next_table_ids, Next_table_ids}];

decode(#ofp_table_feature_prop_write_actions{ action_ids = Action_ids }) ->
    Action_ids;

decode(#ofp_table_feature_prop_write_actions_miss{ action_ids = Action_ids }) ->
    [{action_ids, Action_ids}];

decode(#ofp_table_feature_prop_apply_actions{ action_ids = Action_ids }) ->
    [{action_ids, Action_ids}];

decode(#ofp_table_feature_prop_apply_actions_miss{ action_ids = Action_ids }) ->
    [{action_ids, Action_ids}];

decode(#ofp_table_feature_prop_match{ oxm_ids = Oxm_ids }) ->
    [{oxm_ids, Oxm_ids}];

decode(#ofp_table_feature_prop_wildcards{ oxm_ids = Oxm_ids }) ->
    [{oxm_ids, Oxm_ids}];

decode(#ofp_table_feature_prop_write_setfield{ oxm_ids = Oxm_ids }) ->
    [{oxm_ids, Oxm_ids}];

decode(#ofp_table_feature_prop_write_setfield_miss{ oxm_ids = Oxm_ids }) ->
    [{oxm_ids, Oxm_ids}];

decode(#ofp_table_feature_prop_apply_setfield{ oxm_ids = Oxm_ids }) ->
    [{oxm_ids, Oxm_ids}];

decode(#ofp_table_feature_prop_apply_setfield_miss{ oxm_ids = Oxm_ids }) ->
    [{oxm_ids, Oxm_ids}];

decode(#ofp_table_feature_prop_experimenter{
          experimenter = Experimenter,
          exp_type = Exp_type,
          data = Data
         }) ->
    [{experimenter, Experimenter},
     {exp_type, Exp_type},
     {data, Data}];

decode(#ofp_table_feature_prop_experimenter_miss{
          experimenter = Experimenter,
          exp_type = Exp_type,
          data = Data
         }) ->
    [{experimenter, Experimenter},
     {exp_type, Exp_type},
     {data, Data}];

decode(#ofp_table_features{
          table_id = Table_id,
          name = Name,
          metadata_match = Metadata_match,
          metadata_write = Metadata_write,
          max_entries = Max_entries,
          properties = Properties
         }) ->
    [{table_id, Table_id},
     {name, Name},
     {metadata_match, Metadata_match},
     {metadata_write, Metadata_write},
     {max_entries, Max_entries},
     {properties, Properties}];

decode(#ofp_table_features_reply{ flags = Flags, body = Body }) ->
    [{flags, Flags},
     {body, Body}];

decode(#ofp_port_stats{
          port_no = Port_no,
          rx_packets = Rx_packets,
          tx_packets = Tx_packets,
          rx_bytes = Rx_bytes,
          tx_bytes = Tx_bytes,
          rx_dropped = Rx_dropped,
          tx_dropped = Tx_dropped,
          rx_errors = Rx_errors,
          tx_errors = Tx_errors,
          rx_frame_err = Rx_frame_err,
          rx_over_err = Rx_over_err,
          rx_crc_err = Rx_crc_err,
          collisions = Collisions,
          duration_sec = Duration_sec,
          duration_nsec = Duration_nsec
         }) ->
    [{port_no, Port_no},
     {rx_packets, Rx_packets},
     {tx_packets, Tx_packets},
     {rx_bytes, Rx_bytes},
     {tx_bytes, Tx_bytes},
     {rx_dropped, Rx_dropped},
     {tx_dropped, Tx_dropped},
     {rx_errors, Rx_errors},
     {tx_errors, Tx_errors},
     {rx_frame_err, Rx_frame_err},
     {rx_over_err, Rx_over_err},
     {rx_crc_err, Rx_crc_err},
     {collisions, Collisions},
     {duration_sec, Duration_sec},
     {duration_nsec, Duration_nsec}];

decode(#ofp_port_stats_reply{ flags = Flags, body = Body }) ->
    [{flags, Flags},
     {body, Body}];

decode(#ofp_port_desc_reply{ flags = Flags, body = Body }) ->
    [{flags, Flags},
     {body, Body}];

decode(#ofp_queue_stats{
          port_no = Port_no,
          queue_id = Queue_id,
          tx_bytes = Tx_bytes,
          tx_packets = Tx_packets,
          tx_errors = Tx_errors,
          duration_sec = Duration_sec,
          duration_nsec = Duration_nsec
         }) ->
    [{port_no, Port_no},
     {queue_id, Queue_id},
     {tx_bytes, Tx_bytes},
     {tx_packets, Tx_packets},
     {tx_errors, Tx_errors},
     {duration_sec, Duration_sec},
     {duration_nsec, Duration_nsec}];

decode(#ofp_queue_stats_reply{ flags = Flags, body = Body }) ->
    [{flags, Flags},
     {body, Body}];

decode(#ofp_bucket_counter{ packet_count = Packet_count, byte_count = Byte_count }) ->
    [{packet_count, Packet_count},
     {byte_count, Byte_count}];

decode(#ofp_group_stats{
          group_id = Group_id,
          ref_count = Ref_count,
          packet_count = Packet_count,
          byte_count = Byte_count,
          duration_sec = Duration_sec,
          duration_nsec = Duration_nsec,
          bucket_stats = Bucket_stats
         }) ->
    [{group_id, Group_id},
     {ref_count, Ref_count},
     {packet_count, Packet_count},
     {byte_count, Byte_count},
     {duration_sec, Duration_sec},
     {duration_nsec, Duration_nsec},
     {bucket_stats, Bucket_stats}];

decode(#ofp_group_stats_reply{ flags = Flags, body = Body }) ->
    [{flags, Flags},
     {body, Body}];

decode(#ofp_group_desc_stats{
          type = Type,
          group_id = Group_id,
          buckets = Buckets
         }) ->
    [{type, Type},
     {group_id, Group_id},
     {buckets, [decode(Bucket) || Bucket <- Buckets]}];

decode(#ofp_group_desc_reply{ flags = Flags, body = Body }) ->
    [{flags, Flags},
     {body, Body}];

decode(#ofp_group_features_reply{
          flags = Flags,
          types = Types,
          capabilities = Capabilities,
          max_groups = Max_groups
         }) ->
    [{flags, Flags},
     {types, Types},
     {capabilities, Capabilities},
     {max_groups, Max_groups}];

decode(#ofp_meter_band_stats{
          packet_band_count = Packet_band_count,
          byte_band_count = Byte_band_count
         }) ->
    [{packet_band_count, Packet_band_count},
     {byte_band_count, Byte_band_count}];

decode(#ofp_meter_stats{
          meter_id = Meter_id,
          flow_count = Flow_count,
          packet_in_count = Packet_in_count,
          byte_in_count = Byte_in_count,
          duration_sec = Duration_sec,
          duration_nsec = Duration_nsec,
          band_stats = Band_stats
         }) ->
    [{meter_id, Meter_id},
     {flow_count, Flow_count},
     {packet_in_count, Packet_in_count},
     {byte_in_count, Byte_in_count},
     {duration_sec, Duration_sec},
     {duration_nsec, Duration_nsec},
     {band_stats, Band_stats}];

decode(#ofp_meter_stats_reply{ flags = Flags, body = Body
         }) ->
    [{flags, Flags},
     {body, Body}];

decode(#ofp_meter_config{
          flags = Flags,
          meter_id = Meter_id,
          bands = Bands
         }) ->
    [{flags, Flags},
     {meter_id, Meter_id},
     {bands, Bands}];

decode(#ofp_meter_config_reply{ flags = Flags, body = Body }) ->
    [{flags, Flags},
     {body, Body}];

decode(#ofp_meter_features_reply{
          flags = Flags,
          max_meter = Max_meter,
          band_types = Band_types,
          capabilities = Capabilities,
          max_bands = Max_bands,
          max_color = Max_color
         }) ->
    [{flags, Flags},
     {max_meter, Max_meter},
     {band_types, Band_types},
     {capabilities, Capabilities},
     {max_bands, Max_bands},
     {max_color, Max_color}];

decode(#ofp_experimenter_reply{
          flags = Flags,
          experimenter = Experimenter,
          exp_type = Exp_type,
          data = Data
         }) ->
    [{flags, Flags},
     {experimenter, Experimenter},
     {exp_type, Exp_type},
     {data, Data}];

decode(#ofp_queue_get_config_reply{
          port = Port,
          queues = Queues
         }) ->
    [{port, Port},
     {queues, Queues}];

decode(#ofp_barrier_reply{}) ->
    [];

decode(#ofp_role_reply{
          role = Role,
          generation_id = Generation_id
         }) ->
    [{role, Role},
     {generation_id, Generation_id}];

decode(#ofp_get_async_reply{
          packet_in_mask = Packet_in_mask,
          port_status_mask = Port_status_mask,
          flow_removed_mask = Flow_removed_mask
         }) ->
    [{packet_in_mask, Packet_in_mask},
     {port_status_mask, Port_status_mask},
     {flow_removed_mask, Flow_removed_mask}];

decode(#ofp_packet_in{
          buffer_id = Buffer_id,
          reason = Reason,
          table_id = Table_id,
          cookie = Cookie,
          match = Match
         }) ->
    [{buffer_id, Buffer_id},
     {reason, Reason},
     {table_id, Table_id},
     {cookie, Cookie},
     {match, decode_match(Match)}];

decode(#ofp_flow_removed{
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
         }) ->
    [{cookie, Cookie},
     {priority, Priority},
     {reason, Reason},
     {table_id, Table_id},
     {duration_sec, Duration_sec},
     {duration_nsec, Duration_nsec},
     {idle_timeout, Idle_timeout},
     {hard_timeout, Hard_timeout},
     {packet_count, Packet_count},
     {byte_count, Byte_count},
     {match, decode_match(Match)}];

decode(#ofp_port_status{
          reason = Reason,
          desc = Desc
         }) ->
    [{reason, Reason},
     {desc, Desc}];

decode(#ofp_error_msg{
          type = Type,
          code = Code,
          data = Data
         }) ->
    [{type, Type},
     {code, Code},
     {data, Data}];

decode(#ofp_error_msg_experimenter{
          exp_type = Exp_type,
          experimenter = Experimenter,
          data = Data
         }) ->
    [{exp_type, Exp_type},
     {experimenter, Experimenter},
     {data, Data}];

decode(#ofp_echo_request{ data = Data }) ->
    [{data, Data}];

decode(#ofp_echo_reply{ data = Data }) ->
    [{data, Data}];

decode(#ofp_experimenter{
          experimenter = Experimenter,
          exp_type = Exp_type,
          data = Data
         }) ->
    [{experimenter, Experimenter},
     {exp_type, Exp_type},
     {data, Data}].

decode_actions(Actions) ->
    [decode(A) || A <- Actions].

decode_instructions(Is) ->
    [decode(I) || I <- Is].

decode_match(#ofp_match{ fields = Fields }) ->
    [decode_field(F) || F <- Fields].

decode_field(#ofp_field{ name = Name, value = Val, has_mask = true, mask = Mask }) ->
    {Name, Val, Mask};
decode_field(#ofp_field{ name = Name, value = Val, has_mask = false }) ->
    {Name, Val}.
