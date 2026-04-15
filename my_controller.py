from pox.core import core
from pox.lib.util import dpid_to_str
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.arp import arp
from pox.lib.packet.ipv4 import ipv4
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr, EthAddr

log = core.getLogger()

# ------------------------------------------------------------------ #
#  Firewall: bidirectional block between h1 and h3                    #
#  linear,3 with --mac assigns:                                       #
#    h1 = 10.0.0.1,  h2 = 10.0.0.2,  h3 = 10.0.0.3                 #
# ------------------------------------------------------------------ #
BLOCKED_PAIRS = [
    (IPAddr("10.0.0.1"), IPAddr("10.0.0.3")),
    (IPAddr("10.0.0.3"), IPAddr("10.0.0.1")),
]


class MultiSwitchController(object):

    def __init__(self):
        # mac_table[dpid][mac] = port
        self.mac_table = {}
        # flow_stats[(dpid, src_mac, dst_mac)] = packet count
        self.flow_stats = {}
        core.openflow.addListeners(self)
        log.info("=== MultiSwitchController initialized ===")

    # ------------------------------------------------------------------ #
    #  Utility: check if IP pair is blocked                               #
    # ------------------------------------------------------------------ #

    def _is_blocked(self, src_ip, dst_ip):
        return (src_ip, dst_ip) in BLOCKED_PAIRS

    # ------------------------------------------------------------------ #
    #  Utility: install a flow rule on a switch                           #
    # ------------------------------------------------------------------ #

    def _install_flow(self, connection, match, actions,
                      priority=1, idle_timeout=30, hard_timeout=120):
        msg = of.ofp_flow_mod()
        msg.match = match
        msg.priority = priority
        msg.idle_timeout = idle_timeout
        msg.hard_timeout = hard_timeout
        msg.actions = actions
        connection.send(msg)

    # ------------------------------------------------------------------ #
    #  Utility: send packet out                                           #
    # ------------------------------------------------------------------ #

    def _send_packet_out(self, event, out_port):
        msg = of.ofp_packet_out()
        msg.data = event.ofp
        msg.in_port = event.port
        msg.actions.append(of.ofp_action_output(port=out_port))
        event.connection.send(msg)

    # ------------------------------------------------------------------ #
    #  Install firewall DROP rules on switch connect                      #
    # ------------------------------------------------------------------ #

    def _install_firewall_rules(self, connection):
        for (src_ip, dst_ip) in BLOCKED_PAIRS:
            match = of.ofp_match()
            match.dl_type = ethernet.IP_TYPE
            match.nw_src = src_ip
            match.nw_dst = dst_ip

            # Empty actions list = DROP
            # Priority 100 beats all learning switch flows (priority 1)
            self._install_flow(
                connection,
                match=match,
                actions=[],          # DROP
                priority=100,
                idle_timeout=0,      # Never expire
                hard_timeout=0
            )
            log.info("FIREWALL: DROP rule installed %s -> %s on dpid=%s",
                     src_ip, dst_ip, dpid_to_str(connection.dpid))

    # ------------------------------------------------------------------ #
    #  Switch connected                                                   #
    # ------------------------------------------------------------------ #

    def _handle_ConnectionUp(self, event):
        dpid = event.dpid
        self.mac_table[dpid] = {}
        log.info("Switch CONNECTED: dpid=%s", dpid_to_str(dpid))

        # Install firewall rules immediately on every switch
        self._install_firewall_rules(event.connection)

    # ------------------------------------------------------------------ #
    #  Switch disconnected                                                #
    # ------------------------------------------------------------------ #

    def _handle_ConnectionDown(self, event):
        dpid = event.dpid
        self.mac_table.pop(dpid, None)
        log.info("Switch DISCONNECTED: dpid=%s", dpid_to_str(dpid))

    # ------------------------------------------------------------------ #
    #  Packet In                                                          #
    # ------------------------------------------------------------------ #

    def _handle_PacketIn(self, event):
        dpid = event.dpid
        in_port = event.port
        packet = event.parsed

        if not packet.parsed:
            log.warning("Unparsed packet on dpid=%s — ignoring", dpid_to_str(dpid))
            return

        src_mac = packet.src
        dst_mac = packet.dst

        # Ensure MAC table entry exists for this switch
        if dpid not in self.mac_table:
            self.mac_table[dpid] = {}

        # ---- MAC Learning -------------------------------------------- #
        self.mac_table[dpid][src_mac] = in_port
        log.debug("LEARNED: MAC %s on port %s on dpid=%s",
                  src_mac, in_port, dpid_to_str(dpid))

        # ---- ARP Handling -------------------------------------------- #
        if packet.type == ethernet.ARP_TYPE:
            arp_pkt = packet.payload
            op = "REQUEST" if arp_pkt.opcode == arp.REQUEST else "REPLY"
            log.info("ARP %s: who-has %s tell %s | dpid=%s port=%s",
                     op, arp_pkt.protodst, arp_pkt.protosrc,
                     dpid_to_str(dpid), in_port)
            # Flood all ARP packets so hosts can resolve MACs
            self._send_packet_out(event, of.OFPP_FLOOD)
            return

        # ---- IP Firewall Check --------------------------------------- #
        if packet.type == ethernet.IP_TYPE:
            ip_pkt = packet.payload
            src_ip = ip_pkt.srcip
            dst_ip = ip_pkt.dstip

            if self._is_blocked(src_ip, dst_ip):
                log.warning("FIREWALL: BLOCKED %s -> %s on dpid=%s port=%s",
                             src_ip, dst_ip, dpid_to_str(dpid), in_port)
                # Flow rule already installed at ConnectionUp
                # Just drop this packet — send nothing back
                return

        # ---- MAC Learning Forward / Flood ---------------------------- #
        if dst_mac in self.mac_table.get(dpid, {}):
            out_port = self.mac_table[dpid][dst_mac]

            log.info("FORWARD: %s -> %s | port %s -> %s | dpid=%s",
                     src_mac, dst_mac, in_port, out_port, dpid_to_str(dpid))

            # Track flow stats
            key = (dpid, str(src_mac), str(dst_mac))
            self.flow_stats[key] = self.flow_stats.get(key, 0) + 1
            log.info("FLOW STATS: %s -> %s | packet_count=%d",
                     src_mac, dst_mac, self.flow_stats[key])

            # Install forward flow rule
            match = of.ofp_match()
            match.dl_dst = dst_mac
            match.in_port = in_port
            actions = [of.ofp_action_output(port=out_port)]
            self._install_flow(
                event.connection,
                match=match,
                actions=actions,
                priority=1,
                idle_timeout=30,
                hard_timeout=120
            )

            # Also send this current packet out immediately
            self._send_packet_out(event, out_port)

        else:
            # Destination unknown — flood
            log.info("FLOOD: Unknown dst %s on dpid=%s", dst_mac, dpid_to_str(dpid))
            self._send_packet_out(event, of.OFPP_FLOOD)

    # ------------------------------------------------------------------ #
    #  Flow Stats Reply (triggered by ovs-ofctl or periodic query)        #
    # ------------------------------------------------------------------ #

    def _handle_FlowStatsReceived(self, event):
        dpid = dpid_to_str(event.connection.dpid)
        log.info("========== FLOW TABLE: dpid=%s ==========", dpid)
        for stat in event.stats:
            status = "ACTIVE" if stat.packet_count > 0 else "UNUSED"
            log.info("[%s] priority=%s match=%s | packets=%d bytes=%d",
                     status, stat.priority, stat.match,
                     stat.packet_count, stat.byte_count)
        log.info("==========================================")


# ------------------------------------------------------------------ #
#  POX entry point                                                    #
# ------------------------------------------------------------------ #

def launch():
    core.registerNew(MultiSwitchController)
    log.info("Multi-Switch Flow Table Analyzer launched")
