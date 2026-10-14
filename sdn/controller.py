#!/usr/bin/env python3
"""
PropGuard: Ryu SDN Controller (OpenFlow 1.3)
Integrates L2/L3 learning switch logic, periodic flow statistics collection,
and REST-driven graduated defense enforcement.
"""

import json
from webob import Response
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub
from ryu.lib.packet import packet, ethernet, ether_types, ipv4
from ryu.app.wsgi import ControllerBase, WSGIApplication, route

PROPGUARD_INSTANCE = 'propguard_api_app'
BASE_URL = '/propguard'


class PropGuardController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'wsgi': WSGIApplication}

    def __init__(self, *args, **kwargs):
        super(PropGuardController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}
        self.flow_stats_cache = {}

        # Register REST WSGI controller
        wsgi = kwargs['wsgi']
        wsgi.register(PropGuardRESTController, {PROPGUARD_INSTANCE: self})

        # Background thread to poll switch flow stats every 2 seconds
        self.monitor_thread = hub.spawn(self._monitor)

    def _monitor(self):
        while True:
            for dp in list(self.datapaths.values()):
                self._request_stats(dp)
            hub.sleep(2)

    def _request_stats(self, datapath):
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, CONFIG_DISPATCHER])
    def state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.datapaths[datapath.id] = datapath
        elif ev.state == CONFIG_DISPATCHER:
            if datapath.id in self.datapaths:
                del self.datapaths[datapath.id]

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        self.datapaths[datapath.id] = datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Table-miss entry: direct unmatched packets to controller
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, priority=0, match=match, actions=actions)
        self.logger.info(f"Switch s{datapath.id} registered and configured.")

    def add_flow(self, datapath, priority, match, actions, buffer_id=None, idle_timeout=0, hard_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath,
            buffer_id=buffer_id or ofproto.OFP_NO_BUFFER,
            priority=priority,
            match=match,
            instructions=inst,
            idle_timeout=idle_timeout,
            hard_timeout=hard_timeout
        )
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dst = eth.dst
        src = eth.src
        dpid = datapath.id

        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        out_port = self.mac_to_port[dpid].get(dst, ofproto.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            ip_pkt = pkt.get_protocol(ipv4.ipv4)
            if ip_pkt:
                # Install IP flow match so flow stats capture ipv4_src and ipv4_dst
                match = parser.OFPMatch(
                    in_port=in_port,
                    eth_type=ether_types.ETH_TYPE_IP,
                    ipv4_src=ip_pkt.src,
                    ipv4_dst=ip_pkt.dst
                )
                self.add_flow(datapath, priority=10, match=match, actions=actions, idle_timeout=20)
            else:
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
                self.add_flow(datapath, priority=1, match=match, actions=actions, idle_timeout=20)

        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data
        )
        datapath.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        dpid = ev.msg.datapath.id
        body = ev.msg.body
        stats_list = []
        for stat in body:
            match_dict = {k: v for k, v in stat.match.items()}
            stats_list.append({
                'packet_count': stat.packet_count,
                'byte_count': stat.byte_count,
                'duration_sec': stat.duration_sec,
                'priority': stat.priority,
                'match': match_dict
            })
        self.flow_stats_cache[dpid] = stats_list

    # ---------------- Graduated Defense Actions ----------------

    def enforce_isolate(self, target_ip):
        self.logger.warning(f"[PROP-GUARD] ENFORCING FULL ISOLATION ON: {target_ip}")
        for dp in self.datapaths.values():
            parser = dp.ofproto_parser
            match_out = parser.OFPMatch(eth_type=0x0800, ipv4_src=target_ip)
            self.add_flow(dp, priority=100, match=match_out, actions=[])
            match_in = parser.OFPMatch(eth_type=0x0800, ipv4_dst=target_ip)
            self.add_flow(dp, priority=100, match=match_in, actions=[])

    def enforce_soft_quarantine(self, target_ip, sink_ip="10.0.3.99"):
        self.logger.warning(f"[PROP-GUARD] ENFORCING SOFT QUARANTINE ON: {target_ip} -> {sink_ip}")
        for dp in self.datapaths.values():
            parser = dp.ofproto_parser
            match = parser.OFPMatch(eth_type=0x0800, ipv4_src=target_ip)
            actions = [
                parser.OFPActionSetField(ipv4_dst=sink_ip),
                parser.OFPActionOutput(dp.ofproto.OFPP_NORMAL)
            ]
            self.add_flow(dp, priority=90, match=match, actions=actions, idle_timeout=60)

    def enforce_rate_limit(self, target_ip):
        self.logger.warning(f"[PROP-GUARD] ENFORCING RATE-LIMIT ON: {target_ip}")
        for dp in self.datapaths.values():
            parser = dp.ofproto_parser
            match = parser.OFPMatch(eth_type=0x0800, ip_proto=6, ipv4_src=target_ip)
            self.add_flow(dp, priority=80, match=match, actions=[], idle_timeout=5)


class PropGuardRESTController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(PropGuardRESTController, self).__init__(req, link, data, **config)
        self.app = data[PROPGUARD_INSTANCE]

    @route('propguard', BASE_URL + '/topology', methods=['GET'])
    def get_topology(self, req, **kwargs):
        active_dpids = list(self.app.datapaths.keys())
        return Response(content_type='application/json', text=json.dumps({"active_switches": active_dpids}))

    @route('propguard', BASE_URL + '/stats/flows/{dpid}', methods=['GET'])
    def get_flow_stats(self, req, dpid, **kwargs):
        stats = self.app.flow_stats_cache.get(int(dpid), [])
        return Response(content_type='application/json', text=json.dumps({str(dpid): stats}))

    @route('propguard', BASE_URL + '/enforce', methods=['POST'])
    def apply_enforcement(self, req, **kwargs):
        try:
            body = req.json if req.body else {}
            target_ip = body.get('target_ip')
            tier = body.get('tier')
            reason = body.get('reason', 'unspecified')

            if not target_ip or not tier:
                return Response(status=400, text=json.dumps({"error": "Missing target_ip or tier"}))

            if tier == 'isolate':
                self.app.enforce_isolate(target_ip)
            elif tier == 'quarantine':
                self.app.enforce_soft_quarantine(target_ip)
            elif tier == 'rate_limit':
                self.app.enforce_rate_limit(target_ip)
            else:
                return Response(status=400, text=json.dumps({"error": f"Unknown tier {tier}"}))

            return Response(content_type='application/json', text=json.dumps({
                "status": "success",
                "enforced_tier": tier,
                "target_ip": target_ip,
                "reason": reason
            }))
        except Exception as e:
            return Response(status=500, text=json.dumps({"error": str(e)}))
