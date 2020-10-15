#!/usr/bin/python
# -*- coding: utf-8 -*-
import re
import pprint
import time
from datetime import datetime, date, time
from noc.lib import ip
# from noc.lib.boba import liboba_RA_section_counts as liboba
from noc.lib.boba import liboba_RA_section_counts_v2 as liboba
from noc.lib.boba import const
from noc.sa.models.managedobject import ManagedObject
from noc.sa.models.managedobject import ManagedObjectAttribute
# from noc.lib.boba.test_olga import test_libolga_v3_13_1 as libolga
from noc.lib.boba.test_olga import test_libolga_v4_6_3 as libolga


class IPv4WithGw(ip.IPv4):
    """
    MSA-6345

    Subclass of noc.lib.IPv4 with encapsulated gw_addr.
    Use it to represent ip address and subnet on subscriber-interface.

    Look at https://ticket.ertelecom.ru/browse/MSA-6345 for more details.
    """
    def __init__(self, prefix, netmask=None, gw_addr=None):
        """Parameters
        ----------
        gw_addr: str
            `gw-ip-address` from address string of subscriber-interface.
        """
        self.gw_addr = gw_addr
        ip.IPv4.__init__(self, prefix, netmask)


@pyrule
def rule(managed_object, config):
    return liboba.run_check(managed_object, config, check, 'alcfgche2.py')


CHK_WRNG_CNST_ALU = {
    # 100001:(2, 'WARNING','ALUCHKMISC','vprn shutdown'),
    # 100002:(2, 'WARNING','ALUCHKMISC','aaa radius'),
    100003: (2, 'WARNING', 'ALUCHKMISC', 'subscriber-interface not kb', 'MRI'),
    100009: (50, '!!PPC!!', 'ALUCHKSCRT', 'prof admin', 'MRI'),

    104001: (0, 'ERROR  ', 'ALUCHKPOOL', 'pool intercross', 'MRI', 'PPPoE'),
    104002: (3, 'ERROR  ', 'ALUCHKPOOL', 'pool cross null', 'MRI'),
    104003: (20, 'ERROR  ', 'ALUCHKPOOL', 'pool with drain', 'MRI'),
    104004: (0, 'INFO   ', 'ALUCHKPOOL', 'dhcp server existance', 'MRI', 'DHCP'),
    104005: (0, 'INFO   ', 'ALUCHKPOOL', 'dhcp pool existance', 'MRI', 'DHCP'),
    104006: (0, 'INFO   ', 'ALUCHKPOOL', 'dhcp net existance', 'MRI', 'DHCP'),
    104011: (5, 'INFO   ', 'ALUCHKPOOL', 'dhcp srv nf', 'MRI', 'DHCP'),
    104012: (5, 'INFO   ', 'ALUCHKPOOL', 'subs iface nf', 'MRI', 'DHCP'),
    104013: (5, 'INFO   ', 'ALUCHKPOOL', 'ip net nf in iface', 'MRI', 'DHCP'),
    104014: (1, 'INFO   ', 'ALUCHKPOOL', 'the more specific route', 'MRI', 'DHCP'),
    104020: (0, 'INFO   ', 'ALUCHKPOOL', 'dhcp pool lease', 'MRI', 'DHCP'),
    104021: (0, 'INFO   ', 'ALUCHKPOOL', 'dhcp failover ip', 'MRI', 'DHCP'),
    104022: (0, 'INFO   ', 'ALUCHKPOOL', 'dhcp failover tag', 'MRI', 'DHCP'),
    104023: (0, 'INFO   ', 'ALUCHKPOOL', 'dhcp failover sh', 'MRI', 'DHCP'),
    104024: (0, 'INFO   ', 'ALUCHKPOOL', 'loopback105 nf', 'MRI', 'DHCP'),
    104025: (0, 'INFO   ', 'ALUCHKPOOL', 'loopback105 desc', 'MRI', 'DHCP'),
    104026: (0, 'INFO   ', 'ALUCHKPOOL', 'loopback105 dhcpv4', 'MRI', 'DHCP'),
    104027: (0, 'INFO   ', 'ALUCHKPOOL', 'loopback105 dhcpv6', 'MRI', 'DHCP'),
    104028: (0, 'INFO   ', 'ALUCHKPOOL', 'loopback105 sec ip', 'MRI', 'DHCP'),
    104030: (0, 'INFO   ', 'ALUCHKPOOL', 'sub-def dhcp6 nf', 'MRI', 'DHCP'),
    104031: (0, 'INFO   ', 'ALUCHKPOOL', 'sub-def dhcp6 src_addr', 'MRI', 'DHCP'),
    104032: (0, 'INFO   ', 'ALUCHKPOOL', 'sub-def dhcp6 lnk_addr', 'MRI', 'DHCP'),
    104033: (0, 'INFO   ', 'ALUCHKPOOL', 'sub-def dhcp6 srv_addr', 'MRI', 'DHCP'),
    104034: (0, 'INFO   ', 'ALUCHKPOOL', 'sub-def dhcp6 proxy nf', 'MRI', 'DHCP'),
    104035: (0, 'INFO   ', 'ALUCHKPOOL', 'sub-def dhcp6 proxy sh', 'MRI', 'DHCP'),
    104036: (0, 'INFO   ', 'ALUCHKPOOL', 'sub-def dhcp6 relay nf', 'MRI', 'DHCP'),
    104037: (0, 'INFO   ', 'ALUCHKPOOL', 'sub-def dhcp6 relay sh', 'MRI', 'DHCP'),
    104038: (0, 'INFO   ', 'ALUCHKPOOL', 'sub-def proxy lease', 'MRI', 'DHCP'),
    104039: (0, 'INFO   ', 'ALUCHKPOOL', 'sub-def dhcp sh', 'MRI', 'DHCP'),
    104040: (0, 'INFO   ', 'ALUCHKPOOL', 'sub-def dhcp emu-srv gi-add', 'MRI', 'DHCP'),
    104041: (0, 'INFO   ', 'ALUCHKPOOL', 'sub-def shcv-policy', 'MRI', 'DHCP'),
    104042: (0, 'INFO   ', 'ALUCHKPOOL', 'sub-def srrp nf', 'MRI', 'DHCP'),
    104043: (0, 'INFO   ', 'ALUCHKPOOL', 'sub-def srrp sh', 'MRI', 'DHCP'),
    104044: (0, 'INFO   ', 'ALUCHKPOOL', 'sub-def srrp prior', 'MRI', 'DHCP'),
    104045: (0, 'INFO   ', 'ALUCHKPOOL', 'vprn 100 dhcp pools', 'MRI', 'DHCP'),

    104100: (0, 'INFO   ', 'ALUCHKPOOL', 'shcv-policy', 'MRI', 'DHCP'),
    104101: (0, 'INFO   ', 'ALUCHKPOOL', 'pl-radius-srv nf', 'MRI', 'DHCP'),
    104102: (0, 'INFO   ', 'ALUCHKPOOL', 'pl-radius-srv ip nf', 'MRI', 'DHCP'),
    104103: (50, 'WARNING', 'ALUCHKPOOL', 'Main config part', 'MRI'),
    104201: (0, 'INFO   ', 'ALUCHKPOOL', 'IP_prefix, ML-monitoring', 'MRI'),

    107001: (2, 'WARNING', 'ALUCHKGIFS', 'backup host', 'MRI'),
    107002: (3, 'ERROR  ', 'ALUCHKGIFS', 'sap not found', 'MRI', 'IPoE'),
    107003: (1, 'INFO   ', 'ALUCHKGIFS', 'giface empty', 'MRI'),
    107004: (0, 'MAGI   ', 'ALUCHKGIFS', 'giface not ACCESS', 'MRI'),
    107005: (0, 'MAGI   ', 'ALUCHKGIFS', 'ACCESS not giface', 'MRI'),
    107006: (1, 'INFO   ', 'ALUCHKGIFS', 'no saps', 'MRI', 'IPoE'),
    107007: (2, 'WARNING', 'ALUCHKGIFS', 'def-sla-profile not correct', 'MRI', 'DHCP'),
    107008: (0, 'WARNING', 'ALUCHKGIFS', 'sap cpu-protection not correct', 'MRI', 'DHCP'),
    107009: (0, 'WARNING', 'ALUCHKGIFS', 'sap anti-spoof not correct', 'MRI'),
    107010: (0, 'WARNING', 'ALUCHKGIFS', 'mistakes in cpm-filter', 'MRI'),
    107011: (1, 'WARNING', 'ALUCHKGIFS', 'Check host-content listed at group-interface IPOE', 'MRI', 'IPoE'),

    108001: (2, 'WARNING', 'ALUCHKSAPS', 'sap physic', 'MRI'),
    108002: (0, 'MAGI   ', 'ALUCHKSAPS', 'rate in sap vpls', 'MRI'),
    108003: (1, 'MAGI   ', 'ALUCHKSAPS', 'service-mtu greater 9100', 'MRI'),
    108004: (0, 'INFO   ', 'ALUCHKSAPS', 'service-mtu not equal', 'MRI'),
    108011: (0, 'ERROR  ', 'ALUCHKSAPS', 'nocheck vpls numb', 'MRI'),
    108012: (0, 'ERROR  ', 'ALUCHKSAPS', 'mesh-sdp diff numb', 'MRI'),
    108013: (0, 'ERROR  ', 'ALUCHKSAPS', 'mesh-sdp nf', 'MRI'),
    108014: (0, 'ERROR  ', 'ALUCHKSAPS', 'vpls excessive', 'MRI'),
    108015: (0, 'ERROR  ', 'ALUCHKSAPS', 'sap excessive', 'MRI'),
    108016: (0, 'ERROR  ', 'ALUCHKSAPS', 'vpls diff', 'MRI'),
    108017: (0, 'INFO   ', 'ALUCHKSAPS', 'srrp priority equal', 'MRI'),
    108030: (0, 'INFO   ', 'ALUCHKSAPS', 'mesh-sdp but no m-o-g', 'GS'),
    108031: (0, 'INFO   ', 'ALUCHKSAPS', 've-id other vpls nf', 'GS'),
    108032: (0, 'INFO   ', 'ALUCHKSAPS', 've-id equal', 'GS'),
    108033: (0, 'INFO   ', 'ALUCHKSAPS', 've-id equal', 'GS'),
    108034: (0, 'MAGI   ', 'ALUCHKSAPS', 'rate in sap vpls', 'GS'),
    108035: (0, 'INFO   ', 'ALUCHKSAPS', 'vpls2 check priority and entry', 'MRI'),

    111009: (0, 'ERROR  ', 'ALUCHKFILT', 'no acl', 'MRI'),
    116001: (0, 'ERROR  ', 'ALUCHKMTU', 'mtu', 'MRI'),
    116002: (3, 'ERROR  ', 'ALUCHKRES', 'sap resource optimizations', 'MRI'),
    116003: (3, 'ERROR  ', 'ALUCHKMSAP', 'def-sla-profile in msap-policy not correct', 'MRI'),

    113001: (2, 'WARNING', 'ALUCHKQOS', 'qos on sap', 'MRI'),
    113004: (0, 'WARNING', 'ALUCHKQOS', 'qos 10,100,200...', 'MRI'),

    130000: (0, 'WARNING', 'ALUCHKIPTV', 'IPTV vprn shutdown or doesnt exist', 'MRI', 'IPTV'),
    130001: (1, 'WARNING', 'ALUCHKIPTV', 'IPTV interface shutdown or doesnt exist', 'MRI', 'IPTV'),
    130002: (1, 'WARNING', 'ALUCHKIPTV', 'IPTV ip-mtu wrong', 'MRI', 'IPTV'),
    130003: (1, 'WARNING', 'ALUCHKIPTV', 'IPTV qos in(e)gress wrong', 'MRI', 'IPTV'),
    130004: (1, 'WARNING', 'ALUCHKIPTV', 'IPTV bfd wrong', 'MRI', 'IPTV'),
    130005: (1, 'WARNING', 'ALUCHKIPTV', 'IPTV pim shutdown or doesnt exist', 'MRI', 'IPTV'),
    130006: (1, 'WARNING', 'ALUCHKIPTV', 'IPTV bfd-enable wrong', 'MRI', 'IPTV'),
    130007: (1, 'WARNING', 'ALUCHKIPTV', 'IPTV pim rpf-table wrong', 'MRI', 'IPTV'),
    130008: (1, 'WARNING', 'ALUCHKIPTV', 'IPTV pim non-dr-attract-traffic wrong', 'MRI', 'IPTV'),
    130009: (1, 'WARNING', 'ALUCHKIPTV', 'IPTV pim static or anycast address wrong', 'MRI', 'IPTV'),
    130010: (1, 'WARNING', 'ALUCHKIPTV', 'IPTV pim group-prefix wrong', 'MRI', 'IPTV'),
    130011: (1, 'WARNING', 'ALUCHKIPTV', 'IPTV ospf shutdown or doesnt exist', 'MRI', 'IPTV'),
    130012: (0, 'WARNING', 'ALUCHKIPTV', 'IPTV ospf area wrong', 'MRI', 'IPTV'),
    130013: (0, 'WARNING', 'ALUCHKIPTV', 'IPTV ospf area0 shutdown or doesnt exist', 'MRI', 'IPTV'),
    130014: (0, 'WARNING', 'ALUCHKIPTV', 'qos 600', 'MRI', 'IPTV'),
    140001: (0, 'ERROR  ', 'ALUCHKLUDB', 'local-user-db not found', 'MRI', 'DHCP'),
    140002: (0, 'ERROR  ', 'ALUCHKLUDB', 'local-user-db incorrect', 'GS', 'DHCP'),
    140003: (0, 'ERROR  ', 'ALUCHKLUDB', 'host not found', 'MRI', 'DHCP'),
    140004: (0, 'ERROR  ', 'ALUCHKLUDB', 'host excessive', 'MRI', 'DHCP'),
    140005: (0, 'ERROR  ', 'ALUCHKLUDB', 'host incorrect', 'MRI', 'DHCP'),
    141001: (50, 'ERROR  ', 'ALUCHKPADO', 'policy diff', 'MRI', 'PPPoE'),
    142001: (0, 'ERROR  ', 'ALUCHKIPFI', 'ip-filter 300', 'MRI', 'Phones and IPoE Video'),
    142002: (0, 'ERROR  ', 'ALUCHKIPFI', 'ip-filter 300 desc nf', 'MRI', 'Phones and IPoE Video'),
    142003: (0, 'ERROR  ', 'ALUCHKIPFI', 'ip-filter 300 desc err', 'MRI', 'Phones and IPoE Video'),
    142004: (0, 'ERROR  ', 'ALUCHKIPFI', 'ip-filter 300 ent nf', 'MRI', 'Phones and IPoE Video'),
    142005: (0, 'ERROR  ', 'ALUCHKIPFI', 'ip-filter 300 ent ex', 'MRI', 'Phones and IPoE Video'),
    142006: (0, 'ERROR  ', 'ALUCHKIPFI', 'ip-filter 300 ent err', 'MRI', 'Phones and IPoE Video'),

    143001: (0, 'WARNING', 'ALUCHKFI90', 'ip-filter 90 nf', 'MRI'),
    143002: (0, 'WARNING', 'ALUCHKFI90', 'ip-filter 90 ent nf', 'MRI'),
    143003: (0, 'WARNING', 'ALUCHKFI90', 'ip-filter 90 ent ex', 'MRI'),
    143004: (0, 'WARNING', 'ALUCHKFI90', 'ip-filter 90 ctn inv', 'MRI'),

    144001: (0, 'ERROR  ', 'ALUCHKSAPS', 'vpls saps tags', 'MRI'),

    145001: (2, 'ERROR  ', 'ALUCHKIFACE', 'iface has sap, no address', 'GS'),

    146000: (0, 'ERROR  ', 'ALUCHKRADDB', 'RAD-PPPOE-ERTELECOM nf', 'MRI', 'PPPoE'),
    146001: (0, 'ERROR  ', 'ALUCHKRADDB', 'server nf', 'MRI', 'PPPoE'),
    146002: (0, 'ERROR  ', 'ALUCHKRADDB', 'vprn rad src nf', 'MRI', 'PPPoE'),
    146003: (0, 'ERROR  ', 'ALUCHKRADDB', 'vprn rad srv nf', 'MRI', 'PPPoE'),
    146004: (0, 'ERROR  ', 'ALUCHKRADDB', 'vprn rad srv accept-coa', 'MRI', 'PPPoE'),
    146005: (0, 'ERROR  ', 'ALUCHKRADDB', 'ip-pref-list nf', 'MRI', 'PPPoE'),
    146006: (0, 'ERROR  ', 'ALUCHKRADDB', 'vprn rad srv ip nf', 'MRI', 'PPPoE'),
    147001: (0, 'ERROR  ', 'ALUCHKIPOEP', 'subs iface nf', 'GS', 'IPoE'),
    147002: (0, 'ERROR  ', 'ALUCHKIPOEP', 'auth-policy nf', 'GS', 'IPoE'),
    147003: (0, 'ERROR  ', 'ALUCHKIPOEP', 'miss ip in local-user-db', 'GS', 'IPoE'),
    147004: (0, 'ERROR  ', 'ALUCHKIPOEP', 'ip is not longer', 'GS', 'IPoE'),
    147005: (0, 'ERROR  ', 'ALUCHKIPOEP', 'miss ip in prefix-list', 'GS', 'IPoE'),

    148001: (0, 'ERROR  ', 'ALUCHKSPEED', 'speed not listed at description sap', 'MRI', 'ChangeOver'),
    148002: (0, 'ERROR  ', 'ALUCHKSPEED', 'speed on ingress and egress is diffrent', 'MRI'),
    148003: (0, 'ERROR  ', 'ALUCHKSPEED', 'speed on description and rate is diffrent', 'MRI'),

    # for ref
    150101: (0, 'WARNING', 'ALUCHKSAPS', 'Lag, Group-, Sub- interfaces diffrent to double bsr', 'GS'),

    150201: (0, 'WARNING', 'ALUCHKQOSHLS', 'QOS sap-ingress(egress) ->policer/queue', 'MRI', 'HLS'),
    150301: (1, 'WARNING', 'ALUCHKQOSCCTV', 'One diffrent between concept and config', 'MRI', 'HLS'),
    150302: (2, 'WARNING', 'ALUCHKQOSCCTV', 'Two or more diffrent between concept and config', 'MRI', 'HLS'),
    #    150303: (0, 'WARNING', 'ALUCHKQOSCCTV', 'Single diffrent between concept and config', 'MRI', 'check_qos/prefix_CCTV  https://kb.ertelecom.ru/pages/viewpage.action?pageId=127291067'),
    150303: (0, 'WARNING', 'ALUCHKQOSCCTV', 'Single diffrent between concept and config', 'MRI', 'HLS'),

    150401: (0, 'WARNING', 'ALUCHKSDP', 'check endpoint spoke-sdp', 'MRI', 'VPLS'),

    150501: (0, 'WARNING', 'ALUCHKVRRP', 'check VRRP on vprn', 'MRI'),
}


def check(mgmt, config):
    result = {}

    # ____REF_START______________________

    def get_all_bsrs_configs_N():
        current_bsr_name = mgmt.name
        name_parts = re.split('\d\d', current_bsr_name, 1)
        configs_N = {}
        all_bsrs = ManagedObject.objects.filter(name__startswith=name_parts[0], name__endswith=name_parts[1])
        for bsr in all_bsrs:
            bsr_name = str(bsr.name)
            configs_N[bsr_name] = bsr.config.get_gridvcs().get(bsr.id)
        return configs_N

    # d_config[main_bras_name / double_bras_name]['echo "Service Configuration"']['service']['vprns']
    def check_si_and_sap_all_bsr(vprns_01, vprns_02):
        # https://ticket.ertelecom.ru/browse/MSA-11
        result = {}
        for vprn_num_01, vprn_content_01 in (vprns_01).items():
            for vprn_num_02, vprn_content_02 in (vprns_02).items():
                if vprn_num_01 == vprn_num_02:
                    try:
                        for si_01, si_01_content in (vprn_content_01['setap_content']['subscriber_interfaces']).items():
                            result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 150101, result)
                            if si_01 not in (vprn_content_02['setap_content']['subscriber_interfaces']).keys():

                                result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 150101,
                                                             "Subscriber-interface %s (vprn %s) not in double bras"
                                                             % (si_01, vprn_num_02), result)
                            else:
                                for gi_01, gi_01_content in (si_01_content['group_interfaces']).items():
                                    result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 150101, result)
                                    if gi_01 not in (vprn_content_02['setap_content']['subscriber_interfaces'][si_01][
                                        'group_interfaces']).keys():
                                        result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 150101,
                                                                     "Group-interface %s (subscriber-interface %s, vprn %s) not in double bras"
                                                                     % (gi_01, si_01, vprn_num_02), result)
                                    else:
                                        for lag_01 in (gi_01_content['saps']).keys():
                                            result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 150101, result)
                                            if lag_01 not in (
                                                    vprn_content_02['setap_content']['subscriber_interfaces'][si_01][
                                                        'group_interfaces'][gi_01]['saps']).keys():
                                                result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 150101,
                                                                             "Sap %s (group-interface %s, subscriber-interface %s, vprn %s) not in double bras"
                                                                             % (lag_01, gi_01, si_01, vprn_num_02),
                                                                             result)
                    except Exception as ex:
                        print("!!!!Error on content(1) %s: %s" % (vprn_num_01, ex))
                        continue
                    try:
                        for si_02, si_02_content in (vprn_content_02['setap_content']['subscriber_interfaces']).items():
                            result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 150101, result)
                            if si_02 not in (vprn_content_01['setap_content']['subscriber_interfaces']).keys():
                                result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 150101,
                                                             "Subscriber-interface %s (vprn %s) not in this bras"
                                                             % (si_02, vprn_num_01), result)
                            else:
                                for gi_02, gi_02_content in (si_02_content['group_interfaces']).items():
                                    result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 150101, result)
                                    if gi_02 not in (vprn_content_01['setap_content']['subscriber_interfaces'][si_02][
                                        'group_interfaces']).keys():
                                        result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 150101,
                                                                     "Group-interface %s (subscriber-interface %s, vprn %s) not in this bras"
                                                                     % (gi_02, si_02, vprn_num_01), result)
                                    else:
                                        for lag_02 in (gi_02_content['saps']).keys():
                                            result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 150101, result)
                                            if lag_02 not in (
                                                    vprn_content_01['setap_content']['subscriber_interfaces'][si_02][
                                                        'group_interfaces'][gi_02]['saps']).keys():
                                                result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 150101,
                                                                             "Sap %s (group-interface %s, subscriber-interface %s, vprn %s) not in this bras"
                                                                             % (lag_02, gi_02, si_02, vprn_num_01),
                                                                             result)
                    except Exception as ex2:
                        print("!!!!Error on content(2) %s: %s" % (vprn_num_02, ex2))
        result = liboba.add_descr_to_result(result,
                                            "<<<<< check equivalent of name sub, group, lag for double bsr commons >>>>> (%d/%d)")
        return result

    # result_N = check_qos_sap_N(d_config['current']['echo "QoS Policy Configuration" DOUBLE']['qos']['saps'])
    def check_qos_sap_N(d_qossaps):
        # https://ticket.ertelecom.ru/browse/MSA-197
        result = {}

        phrase = 'action fc "h2.video"'
        list_good_ip = ['109.194.233.32/27', '109.195.89.32/27', '109.194.89.32/27',
                        '188.234.153.177/32', '109.194.169.32/27', '188.234.129.128/27',
                        '188.234.129.160/27', '188.234.138.96/27']

        # Check qossap 10 ingress/egress
        list_error = []
        result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 150201, result)
        if '10' in d_qossaps.keys():
            text_error = '';
            flag_key = ''
            errors_key = {'ingressq': 'sap-ingress 10', 'egressq': 'sap-egress 10', '3q': 'queue 3 on sap-ingress 10',
                          'contentq': 'content queue 3 on sap-ingress 10', 'fcs': 'fc on sap-ingress/egress 10',
                          'contentfc': 'content fc h2/h2.video on sap-ingress|egress 10',
                          'contentic': 'content sap-ingress/egress 10', '"h2"fc': 'fc "h2" on sap-ingress 10',
                          '"h2.video"fc': 'fc "h2.video" on sap-ingress 10', 'h2fc': 'fc h2 on sap-ingress 10'}
            try:
                flag_key = 'q'  # queue
                result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 150201, result)
                if 'rate max cir max' not in (d_qossaps['10']['ingress']['queues']['3']['content']):
                    text_error = "Error at speed content queue 3 sap-ingress 10"
                result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 150201, result)
                if '3' not in (d_qossaps['10']['egress']['queues']).keys():
                    text_error = 'Error at sap-egress 10. No queue 3 '
                flag_key = 'fc'  # fc
                result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 150201, result)
                if 'queue 3' not in d_qossaps['10']['ingress']['fcs']['"h2"']['content']:
                    text_error = 'Error at content fc "h2" sap-ingress 10 '
                result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 150201, result)
                if 'profile in' not in d_qossaps['10']['ingress']['fcs']['"h2.video"']['content']:
                    text_error = 'Error at content fc "h2.video" sap-ingress 10 '
                result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 150201, result)
                if ('queue 3' or 'dot1p 4') not in d_qossaps['10']['egress']['fcs']['h2']['content']:
                    text_error = 'Error at content fc "h2" sap-egress 10 '
                flag_key = 'ic'
                result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 150201, result)
                if 'dscp cs5 af42 fc "h2.video"' not in d_qossaps['10']['ingress']['content']:
                    text_error = 'Error at sap-ingress 10. "dscp cs5 af42 fc "h2.video"" not in content'

            except KeyError as ex:
                k_ex = str(ex.args[0]) + flag_key
                text_error = "Error at" + errors_key[k_ex]
        else:
            text_error = 'Error at QOS Policy Configaration. No qos sap-e/ingress 10'
        if text_error != '':
            list_error.append(text_error)
            result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 150201,
                                         "%s"
                                         % (text_error), result)

        # Check qossap 10 ingress
        result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 150201, result)
        if '20' in d_qossaps.keys():
            text_error = ''
            errors_key = {'ingressq': 'sap-ingress 20', '3q': 'queue 3 on sap-ingress 20',
                          'contentq': 'content queue 3 on sap-ingress 20', 'fcs': 'fc on sap-ingress 20',
                          'contentfc': 'content fc h2/h2.video on sap-ingress 20',
                          '"h2"fc': 'fc "h2" on sap-ingress 20',
                          '"h2.video"fc': 'fc "h2.video" on sap-ingress 20', 'ingressipc': 'sap-ingress 20',
                          'ip_criteriaipc': 'ip-criteria on sap-ingress 100',
                          'contentipc': 'content of ip-criteria on sap-ingress 20'
                          }
            flag_key = ''
            try:
                flag_key = 'q'  # queue
                result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 150201, result)
                if 'rate max cir max' not in (d_qossaps['20']['ingress']['queues']['3']['content']):
                    text_error = "Error at speed content queue 3 sap-ingress 20"
                flag_key = 'fc'  # fc
                result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 150201, result)
                if 'queue 3' not in d_qossaps['20']['ingress']['fcs']['"h2"']['content']:
                    text_error = 'content fc "h2" sap-ingress 20 '
                result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 150201, result)
                if ('in-remark dscp af42' or 'out-remark dscp af42' or 'profile in') not in \
                        d_qossaps['20']['ingress']['fcs']['"h2.video"']['content']:
                    text_error = 'Error at content fc "h2.video" sap-egress 20 '
                flag_key = 'ipc'
                for one_ip in list_good_ip:
                    result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 150201, result)
                    if one_ip not in (d_qossaps['20']['ingress']['ip_criteria']['content']):
                        text_error = 'Error at ipcriteria. %s not in ip-criteria sap-ingress 20 ' % (one_ip)
                        break
                    else:
                        for keyone_entry, valone_entry in (
                                d_qossaps['20']['ingress']['ip_criteria']['entries']).items():
                            if one_ip in valone_entry['content']:
                                result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 150201, result)
                                if phrase not in valone_entry['content']:
                                    text_error = 'Error at ipcriteria. %s not under %s' % (phrase, one_ip)
                                    break

            except KeyError as ex:
                k_ex = str(ex.args[0]) + flag_key
                text_error = "Error at " + errors_key[k_ex]
        else:
            text_error = 'Error at QOS Policy Configaration. No qos sap-ingress 20 '
        if text_error != '':
            list_error.append(text_error)
            result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 150201,
                                         "%s"
                                         % (text_error), result)

        # Check qossap 100 ingress
        result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 150201, result)
        if '100' in d_qossaps.keys():
            text_error = ''
            errors_key = {'ingressp': 'sap-ingress 100', 'egressp': 'sap-egress 100',
                          '3p': 'policer 3 on sap-in/egress 100',
                          '2p': 'policer 3 on sap-egress 100', 'contentp': 'content policer 3 on sap-in/egress 100',
                          'fcs': 'fc on sap-in/egress 100', 'ingressfc': 'sap-ingress 100',
                          'egressfc': 'sap-egress 100',
                          'contentfc': 'content fc h2/h2.video on sap-ingress 100',
                          '"h2"fc': 'fc "h2" on sap-ingress 100',
                          'h2fc': 'fc h2 on sap-egress 100',
                          '"h2.video"fc': 'fc "h2.video" on sap-ingress 100', 'ingressipc': 'sap-ingress 100',
                          'ip_criteriaipc': 'ip-criteria on sap-ingress 100',
                          'contentipc': 'content of ip-criteria on sap-ingress 100'
                          }
            flag_key = ''
            try:
                flag_key = 'p'  # queue
                list_phrase_p3 = ['parent "root" level 5', 'rate 50000 cir 30000', 'mbs 4096 kilobytes',
                                  'cbs 4096 kilobytes']
                list_phrase_p2 = ['parent "root" level 7', 'rate 64000 cir 64000', 'mbs 8000 kilobytes',
                                  'cbs 8000 kilobytes']
                list_prase_h2 = ['policer 2', 'dot1p 3', 'dot1p-inner 3', 'dot1p-outer 3']
                for one_prase in list_phrase_p3:
                    result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 150201, result)
                    if one_prase not in (d_qossaps['100']['ingress']['policer']['3']['content']):
                        text_error = "Error at content policer 3 sap-ingress 100"
                        break
                for one_prase in list_phrase_p3:
                    result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 150201, result)
                    if one_prase not in (d_qossaps['100']['egress']['policer']['3']['content']):
                        text_error = "Error at content policer 3 sap-egress 100"
                        break
                for one_prase in list_phrase_p2:
                    result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 150201, result)
                    if one_prase not in (d_qossaps['100']['egress']['policer']['2']['content']):
                        text_error = "Error at content policer 3 sap-egress 100"
                        break
                flag_key = 'fc'  # fc
                result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 150201, result)
                if 'policer 3' not in d_qossaps['100']['ingress']['fcs']['"h2"']['content']:
                    text_error = 'Error on content fc "h2" sap-ingress 100'
                result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 150201, result)
                if ('in-remark dscp af42' or 'out-remark dscp af42' or 'profile in') not in \
                        d_qossaps['100']['ingress']['fcs']['"h2.video"']['content']:
                    text_error = 'Error at content fc "h2.video" sap-ingress 100'
                for one_prase in list_prase_h2:
                    result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 150201, result)
                    if one_prase not in (d_qossaps['100']['egress']['fcs']['h2']['content']):
                        text_error = "Error at content fc h2 sap-egress 100"
                        break
                flag_key = 'ipc'
                for one_ip in list_good_ip:
                    result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 150201, result)
                    if one_ip not in (d_qossaps['100']['ingress']['ip_criteria']['content']):
                        text_error = 'Error at ipcriteria. %s not in ip-criteria sap-ingress 100 ' % (one_ip)
                        break
                    else:
                        for keyone_entry, valone_entry in (
                                d_qossaps['100']['ingress']['ip_criteria']['entries']).items():
                            if one_ip in valone_entry['content']:
                                result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 150201, result)
                                if phrase not in valone_entry['content']:
                                    text_error = 'Error at ipcriteria. %s not under %s' % (phrase, one_ip)
                                    break
            except KeyError as ex:
                k_ex = str(ex.args[0]) + flag_key
                text_error = "Error at" + errors_key[k_ex]
        else:
            text_error = 'Error at QOS Policy Configaration. No qos sap-e/ingress 100 '
        if text_error != '':
            list_error.append(text_error)
            result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 150201,
                                         "%s"
                                         % (text_error), result)

        # Check qossap 110 ingress
        result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 150201, result)
        if '110' in d_qossaps.keys():
            text_error = ''
            errors_key = {'egressp': 'sap-egress 110', '3p': 'policer 3 on sap-egress 110',
                          '2p': 'policer 3 on sap-egress 110', 'contentp': 'content policer 3 on sap-egress 110',
                          'fcs': 'fc on sap-egress 110', 'egressfc': 'sap-egress 110',
                          'contentfc': 'content fc h2 on sap-egress 110', 'h2fc': 'fc h2 on sap-egress 110',
                          }
            flag_key = ''
            try:
                flag_key = 'p'  # queue
                list_phrase_p3 = ['parent "root" level 5', 'rate 50000 cir 30000', 'mbs 4096 kilobytes',
                                  'cbs 4096 kilobytes']
                list_phrase_p2 = ['parent "root" level 7', 'rate 64000 cir 64000', 'mbs 8000 kilobytes',
                                  'cbs 8000 kilobytes']
                list_prase_h2 = ['policer 2', 'dot1p 3', 'dot1p-inner 3', 'dot1p-outer 3']
                for one_prase in list_phrase_p3:
                    result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 150201, result)
                    if one_prase not in (d_qossaps['110']['egress']['policer']['3']['content']):
                        text_error = "Error at content policer 3 sap-egress 110"
                        break
                for one_prase in list_phrase_p2:
                    result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 150201, result)
                    if one_prase not in (d_qossaps['110']['egress']['policer']['2']['content']):
                        text_error = "Error at content policer 3 sap-egress 110"
                        break
                flag_key = 'fc'  # fc
                for one_prase in list_prase_h2:
                    result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 150201, result)
                    if one_prase not in (d_qossaps['110']['egress']['fcs']['h2']['content']):
                        text_error = "Error at content fc h2 sap-egress 110"
                        break
            except KeyError as ex:
                k_ex = str(ex.args[0]) + flag_key
                text_error = "Error at" + errors_key[k_ex]
        else:
            text_error = 'Error at QOS Policy Configaration. No qos sap-e/ingress 110 '
        if text_error != '':
            list_error.append(text_error)
            result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 150201,
                                         "%s"
                                         % (text_error), result)

        result = liboba.add_descr_to_result(result,
                                            "<<<<< check setap QoS for IPTV and Backend in BSR commons (https://kb.ertelecom.ru/pages/viewpage.action?pageId=304363853) >>>>> (%d/%d)")
        return result

    # Part of single check current bsr
    def single_checks_N(system_configuration, cron_configuration):
        result = {}
        # _______DDS-13403__start_____________________________________________________________________________________________________________
        result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 104103, result)
        if system_configuration == '':
            # "ERROR: No system configuration"
            result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 104103,
                                         "Part System in config is not correct", result)
        elif system_configuration != []:
            requests_sysconf = [[], []]
            requests_sysconf[0].append(
                re.compile("(^(?P<space>\s+)script-control\s+.*?^(?P=space)exit$)", re.MULTILINE | re.DOTALL))
            requests_sysconf[0].append(
                re.compile("(^(?P<space>\s+)script \"save_config\".*?^(?P=space)exit$)", re.MULTILINE | re.DOTALL))
            requests_sysconf[0].append(
                re.compile("(^(\s*description \"SAVE CONFIGURATION\"\s*))", re.MULTILINE | re.DOTALL))
            requests_sysconf[0].append(re.compile("(^(\s*location \"cf3\:\\\\save_config\.txt\"\s*))",
                                                  re.MULTILINE | re.DOTALL))  # or ("(^(\s*location\s*\"cf3\:\\save_config\.txt\"\s*))"), re.MULTILINE | re.DOTALL)
            requests_sysconf[0].append(re.compile("(^(\s*no shutdown\s*))", re.MULTILINE | re.DOTALL))
            requests_sysconf[1].append(re.compile("(^(?P<space>\s+)script-policy \"save_config\".*?^(?P=space)exit$)",
                                                  re.MULTILINE | re.DOTALL))
            requests_sysconf[1].append(
                re.compile("(^(\s*results \"cf3\:\\\\save_config_result\.txt\"\s*))", re.MULTILINE | re.DOTALL))
            requests_sysconf[1].append(re.compile("(^(\s*script \"save_config\"\s*))", re.MULTILINE | re.DOTALL))
            requests_sysconf[1].append(re.compile("(^(\s*max-completed 5\s*))", re.MULTILINE | re.DOTALL))
            requests_sysconf[1].append(re.compile("(^(\s*no shutdown\s*))", re.MULTILINE | re.DOTALL))

        responce_sysconf = [[], []]
        for i in [0, 1]:
            responce_sysconf[i] = (requests_sysconf[i][0]).search(system_configuration)
            result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 104103, result)
            if responce_sysconf[i] is not None:
                responce_sysconf[i] = (responce_sysconf[i]).group(1)
            else:
                result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 104103,
                                             "Part System in config is not correct", result)
        if responce_sysconf[i] is not None:
            flag_sc = 0
            for i in [0, 1]:
                count_1 = 0
                for request_sc in requests_sysconf[i]:
                    if count_1 == 0: count_1 += 1;  continue
                    responce_sc = (request_sc.search(responce_sysconf[i]))
                    result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 104103, result)
                    if responce_sc is not None:  #
                        flag_sc = flag_sc + flag_sc
                    else:
                        # "ERROR: No system configuration"
                        flag_sc = flag_sc + 1
                        result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 104103,
                                                     "Part System in config is not correct", result)

            result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 104103, result)
            if flag_sc == 0:
                # "In SysConf All Rigth"
                pass
            else:
                # "We have error"
                result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 104103,
                                             "Part System in config is not correct", result)

        if cron_configuration == '':
            # "ERROR: No cron configuration"
            result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 104103,
                                         "Part Cron in config is not correct", result)
        elif cron_configuration != []:
            requests_cronconf = []
            requests_cronconf.append(
                re.compile("((^(?P<space>\s+)cron\s+.*?^(?P=space)exit$)\s+exit\s+)", re.MULTILINE | re.DOTALL))
            requests_cronconf.append(re.compile("(^(?P<space>\s+)schedule\s*\"save_config\"\s+.*?^(?P=space)exit$)",
                                                re.MULTILINE | re.DOTALL))
            requests_cronconf.append(
                re.compile("(^(\s*description\s*\"SAVE\s*CONFIGURATION\"\s*))", re.MULTILINE | re.DOTALL))
            requests_cronconf.append(re.compile("(^(\s*script-policy\s*\"save_config\"\s*))", re.MULTILINE | re.DOTALL))
            requests_cronconf.append(re.compile("(\s*type\s*calendar\s*)", re.MULTILINE | re.DOTALL))
            requests_cronconf.append(re.compile("(\s*day-of-month\s*all\s*)", re.MULTILINE | re.DOTALL))
            requests_cronconf.append(
                re.compile("(\s*hour\s*9\s*minute\s*0\s*month\s*all\s*weekday\s*all\s*)", re.MULTILINE | re.DOTALL))
            requests_cronconf.append(re.compile("(\s*no\s*shutdown\s*)", re.MULTILINE | re.DOTALL))

        responce_cronconf = []

        responce_cronconf = (requests_cronconf[0]).search(cron_configuration)
        result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 104103, result)
        if responce_cronconf is not None:
            responce_cronconf = (responce_cronconf).group(1)
        else:
            result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 104103,
                                         "Part Cron in config is not correct", result)
        if responce_cronconf is not None:
            flag_cr = 0
            count_2 = 0
            for request_cr in requests_cronconf:
                if count_2 == 0: count_2 += 1;  continue
                responce_cr = (request_cr.search(responce_cronconf))
                result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 104103, result)
                if responce_cr is not None:  #
                    flag_cr = flag_cr + flag_cr
                else:
                    # "ERROR: No system configuration"
                    flag_cr = flag_cr + 1
                    result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 104103,
                                                 "Part Cron in config is not correct", result)

            result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 104103, result)
            if flag_cr == 0:
                # "In CronConf All Rigth"
                pass
            else:
                # "We have error"
                result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 104103,
                                             "Part Cron in config is not correct", result)
        # _______DDS-13403__end_____________________________________________________________________________________________________________

        result = liboba.add_descr_to_result(result, "<<<<< Single checks >>>>> (%d/%d)")
        return result

    # d_config[main_bras_name]['echo "Service Configuration"']['service']['vprns']
    def check_ifaces_N(vprns):
        result_T = {14500: []}
        result = {}
        count_loopback = 0
        for name_vprn, content in vprns.items():
            try:
                for iface in (content['setap_content']['interfaces']).values():
                    result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 145001, result)
                    if 'sap' in iface['content'] and (iface['addr_v4'] == {} and iface['addr_v6'] == {}):
                        result_T[14500].append(iface['if_name'])
                        result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 145001,
                                                     "Iface %s has sap, but no address" % (iface['name']), result)

                    # Check Loopback105
                    if iface['name'] == 'Loopback105':
                        # if_l105 = iface
                        count_loopback += 1
                        params_loopback105 = {104025: {'description': 'DEFAULT-DHCP-ANYCAST'},
                                              104026: {'dhcp_v4': "DEFAULT-DHCP-ANYCAST"},
                                              104027: {'dhcp_v6': "DEFAULT-DHCP-V6-ANYCAST"}
                                              }
                        for code, param in params_loopback105.items():
                            for key, val in param.items():
                                result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 104025, result)
                                if iface[key] != val:
                                    result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, code,
                                                                 "Iface Loopback105 param %s = %s, should be %s." % (
                                                                     key, iface[key], val), result)

                        result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 104028, result)
                        if iface['secondary'] != {}:
                            for sec_ip in (iface['secondary']).values():
                                result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 104028, result)
                                result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 104028,
                                                             "Iface Loopback105, secondary ip %s found."
                                                             % sec_ip, result)
            except Exception as ex:
                print("!!!!Error on content(3) %s: %s" % (name_vprn, ex))
        result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 104024, result)
        if count_loopback == 0:
            result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 104024, "Iface Loopback105 not found", result)

        result = liboba.add_descr_to_result(result, "<<<<< check ifaces commons >>>>> (%d/%d)")

        return result

    def check_ifaces(ifaces):
        result = {}
        for iface in ifaces:
            result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 145001, result)
            if ifaces[iface]['sap'] is not None and ifaces[iface]['addr'] is None:
                result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 145001,
                                             "Iface %s has sap, but no address" % (
                                                 ifaces[iface]['name']), result)

        # Check Loopback105
        result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 104024, result)
        if 'interface "Loopback105"' not in ifaces:
            result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 104024, "Iface Loopback105 not found", result)
        else:
            iface = ifaces['interface "Loopback105"']
            ideal = {
                'desc': {'value': 'DEFAULT-DHCP-ANYCAST', 'code': 104025},
                'dhcp_v4': {'value': 'DEFAULT-DHCP-ANYCAST', 'code': 104026},
                'dhcp_v6': {'value': 'DEFAULT-DHCP-V6-ANYCAST', 'code': 104027},
            }
            for param in ideal:
                real = iface.get(param, 'None')
                value = ideal[param]['value']
                result = liboba.get_war_count(CHK_WRNG_CNST_ALU, ideal[param]['code'], result)
                if real != value:
                    result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, ideal[param]['code'],
                                                 "Iface Loopback105 param %s = %s, should be %s."
                                                 % (param, real, value), result)
            sec_ips = iface.get('secondary', [])
            result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 104028, result)
            for sec_ip in sec_ips:
                result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 104028, result)
                result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 104028,
                                             "Iface Loopback105, secondary ip %s found."
                                             % sec_ip, result)

        result = liboba.add_descr_to_result(result, "<<<<< check ifaces commons >>>>> (%d/%d)")
        return result

    # https://ticket.ertelecom.ru/browse/MSA-190
    def check_prefixes_cctv(real_prefixes, real_qos300in):
        # real_prefixes = d_config[main_bras_name]['echo "Filter Match lists Configuration"']['filter_match_list']['"ML-CCTV-SRV"']['prefixes']
        # qos_300_in = d_config[main_bras_name]['echo "QoS Policy Configuration" DOUBLE']['qos']['saps']['300']['ingress']['ip_criteria']['entries']
        result = {}
        pre_result = []
        with open('/opt/noc/lib/boba/data/prefixes_msa190_00001', 'r') as data_f:
            all_file = data_f.read()
        re_needed_part = re.compile('(configure filter match-list(.*?)$(?P<block_prefixes>.*?)exit)',
                                    re.MULTILINE | re.DOTALL)
        founds_block = re_needed_part.search(all_file)
        if founds_block is None:
            print("ERROR, file from KB.ertelecom was not readed")
            pre_result.append(
                "ERROR, ERROR, PLEASE, SAY ABOUT THIS TO DEPARTMENT AUTOMATIZATION SYSTEM OF MONITORING!!! file from KB.ertelecom was not readed")
            result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 150303,
                                         "ERROR, PLEASE, SAY ABOUT THIS TO DEPARTMENT AUTOMATIZATION SYSTEM OF MONITORING!!! file from KB.ertelecom was not readed",
                                         result)
        else:
            prefixes = founds_block.group('block_prefixes')
            re_pref = re.compile('(\s+prefix\s+(?P<addr_prefix>.*?)$)', re.MULTILINE | re.DOTALL)
            founds_prefixes = re_pref.finditer(prefixes)
            list_addr = []
            for found_prefix in founds_prefixes:
                kb_prefix = found_prefix.group('addr_prefix')
                result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 150303, result)
                if kb_prefix not in real_prefixes.keys():
                    pre_result.append(
                        'Error. ip-prefix %s from kb.ertelecom.ru not in config("ML-CCTV-SRV")' % (kb_prefix))
                    result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 150303,
                                                 'Error. ip-prefix %s from kb.ertelecom.ru not in config("ML-CCTV-SRV")' % (
                                                     kb_prefix), result)

        re_needed_part_qos = re.compile('(configure qos sap-ingress(.*?)$(?P<block_entries>.*?exit)\s+exit)',
                                        re.MULTILINE | re.DOTALL)
        founds_block = re_needed_part_qos.search(all_file)
        if founds_block is None:
            print("ERROR, file from KB.ertelecom was not readed")
            pre_result.append(
                "ERROR, PLEASE, SAY ABOUT THIS TO DEPARTMENT AUTOMATIZATION SYSTEM OF MONITORING!!! file from KB.ertelecom was not readed")
            result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 150303,
                                         "ERROR, PLEASE, SAY ABOUT THIS TO DEPARTMENT AUTOMATIZATION SYSTEM OF MONITORING!!! file from KB.ertelecom was not readed",
                                         result)
        else:
            sap_ingress_300 = founds_block.group('block_entries')
            re_entries = re.compile('^((?P<space>\s+)entry\s+(?P<num>\d+)\s+create(?P<content>.*?)^(?P=space)exit)',
                                    re.MULTILINE | re.DOTALL)
            founds_entries = re_entries.finditer(sap_ingress_300)
            for founds_entry in founds_entries:
                kb_num_entry = founds_entry.group('num')
                kb_content_entry = founds_entry.group('content')
                result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 150303, result)
                try:
                    if kb_content_entry.replace(' ', '') not in (real_qos300in[kb_num_entry]['content']).replace(' ',
                                                                                                                 ''):
                        pre_result.append("Error on content %s at the config" % (kb_num_entry))
                        result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 150303,
                                                     "Error on content %s at the config" % (kb_num_entry), result)

                except Exception as ex:
                    pre_result.append("Error, entry %s not in config" % (kb_num_entry))
                    result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 150303,
                                                 "Error, entry %s not in config" % (kb_num_entry), result)
                    continue

        result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 150301, result)
        result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 150302, result)
        if len(pre_result) == 1:
            result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 150301,
                                         "One diffrent between concept and config", result)
        elif len(pre_result) >= 2:
            result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 150302,
                                         "Two or more diffrent between concept and config", result)

        result = liboba.add_descr_to_result(result,
                                            "<<<<< Check qos and prefixes for CCTV(https://kb.ertelecom.ru/pages/viewpage.action?pageId=127291067) >>>>> (%d/%d)")
        # https://kb.ertelecom.ru/pages/viewpage.action?pageId=127291067
        return result

    # ref__check from all bsr part of ip_prefix_list (DDS-13307)
    def check_ip_prefix_N(ip_prefix_dict):
        # ip_prefix_dict[bsr_name] = d_config[bsr_name]['echo "Filter Match lists Configuration"']['filter_match_list']['"ML-MONITORING"']['prefixes']
        result = {}
        diff = []
        for bsr_1, prefixes_1 in ip_prefix_dict.items():
            for bsr_2, prefixes_2 in ip_prefix_dict.items():
                result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 104201, result)
                if (prefixes_1.keys() == prefixes_2.keys()) or (bsr_1 == bsr_2):
                    continue
                elif (bsr_1 in diff) and (bsr_2 in diff):
                    continue
                else:
                    diff.append(bsr_1)
                    diff.append(bsr_2)
                    result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 104201,
                                                 "Diffrent at ip_prefix_list part ML-Monitoring. %s and %s" % (
                                                     bsr_1, bsr_2), result)
        result = liboba.add_descr_to_result(result,
                                            "<<<<< check ip_prefix_list>>>>> (%d/%d)")
        return result

    # MSA-5868
    def check_endpoint_spoke_sdp(vplss, vplss_double, ip_double_bsr):
        print("start check_endpoint_spoke_sdp")
        result = {}
        if ip_double_bsr == '':
            print("No check endpoint on sdp to double bsr")
        for num_vpls, dict_vpls in vplss.items():
            declare_content = dict_vpls.get('declare_content', {})
            vpls_content = declare_content.get('content', '')
            if vpls_content == '':
                continue
            re_name_endpoint = re.compile('(^\s+endpoint\s+(?P<name_end>\S+)(.*?)create)', re.MULTILINE | re.DOTALL)
            list_endpointes = re_name_endpoint.finditer(vpls_content)
            if list_endpointes == []:
                continue
            for name_endpoint in list_endpointes:
                result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 150401, result)
                name_endpoint = (name_endpoint.group('name_end')).replace('"', '')
                # print(name_endpoint)
                # print()
                re_sdp_endpoint = re.compile('(^\s+spoke-sdp.*?endpoint\s+((\"|)%s(\"|))\s+create)' % (name_endpoint),
                                             re.MULTILINE | re.DOTALL)
                re_mc_endpoint = re.compile('(^\s+mc-endpoint\s+(?P<num_mce>\d+))', re.MULTILINE | re.DOTALL)
                num_mce_current = ''
                if re_mc_endpoint.search(vpls_content) is not None:
                    num_mce_current = (re_mc_endpoint.search(vpls_content)).group('num_mce')
                result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 150401, result)
                if re_sdp_endpoint.search(vpls_content) is None:
                    # print("VPLS %s have endpoint '%s', but haven't spoke-sdp for this endpoint" %(num_vpls, name_endpoint))
                    result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 150401,
                                                 "VPLS %s have endpoint '%s', but haven't spoke-sdp for this endpoint" % (
                                                     num_vpls, name_endpoint), result)
                else:
                    if ip_double_bsr == '':
                        continue
                    re_mc_ep_peer_current = re.compile('(^\s+mc-ep-peer\s+%s)' % (ip_double_bsr),
                                                       re.MULTILINE | re.DOTALL)
                    result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 150401, result)
                    if re_mc_ep_peer_current.search(vpls_content) is None:
                        result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 150401,
                                                     "VPLS %s have endpoint '%s', but this mc-ep-peer ip not equivalent ip double bsr" % (
                                                         num_vpls, name_endpoint), result)
                    if vplss_double == {}:
                        continue
                    try:
                        vpls_content_double = vplss_double[num_vpls]['declare_content']['content']
                        num_mce_double = ''
                        if re_mc_endpoint.search(vpls_content_double) is not None:
                            num_mce_double = (re_mc_endpoint.search(vpls_content_double)).group('num_mce')
                        result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 150401, result)
                        if num_mce_current != num_mce_double or num_mce_double == '':
                            # print("VPLS %s have endpoint '%s', but mc-endpoint(%s) no equivalent with main bsr(%s)" %(num_vpls, name_endpoint, num_mce_current, num_mce_double))
                            result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 150401,
                                                         "VPLS %s have endpoint '%s', but mc-endpoint(%s) no equivalent with main bsr(%s)" % (
                                                             num_vpls, name_endpoint, num_mce_current, num_mce_double),
                                                         result)
                    except Exception as ex:
                        print("!!!!!!error vpls%s double bsr !!!!!!!!!!  %s" % (str(num_vpls), ex))

        result = liboba.add_descr_to_result(result,
                                            "<<<<< check endpoint and spoke-sdp at vpls>>>>> (%d/%d)")
        return result

    # MSA-5861
    def check_vrrp_on_vprns(d_vprns):
        result = {}
        for num_vprn, vprn_content in d_vprns.items():
            setap_content = vprn_content.get('setap_content', {})
            if setap_content == {}:
                continue
            for name_interface, interface_content in setap_content['interfaces'].items():
                content = interface_content.get('content', '')
                if content == '':
                    continue
                if interface_content['shut'] == '' or interface_content['shut'] == 'no':
                    continue
                re_vrrp = re.compile('(^\s+vrrp\s+\d+)', re.MULTILINE | re.DOTALL)
                result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 150501, result)
                if re_vrrp.search(content) is not None:
                    result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 150501,
                                                 "Interface %s (vprn %s) have VRRP and shutdown (Please, remove interface or undo shutdown)"
                                                 % (name_interface, num_vprn), result)

        return result

    # ----REF__END_________________________

    # parsing config for interfaces
    def parse_interfaces(config):
        ifaces = {}
        re_port = re.compile("^(    port .+?)\n    exit$", re.DOTALL | re.MULTILINE)
        re_membport = re.compile("^        port (\S+?) $", re.DOTALL | re.MULTILINE)
        re_lag = re.compile("^(    lag .+?)\n    exit$", re.DOTALL | re.MULTILINE)
        re_siface = re.compile("^            subscriber-interface \"DEFAULT\" create\n(.+?)\n            exit$",
                               re.MULTILINE | re.DOTALL)
        re_sifacei = re.compile("^            subscriber-interface \"IPoE\" create\n(.+?)\n            exit$",
                                re.MULTILINE | re.DOTALL)
        re_sifacew = re.compile(
            "^            subscriber-interface \"DEFAULT-WIFI-DHCP\" create\n(.+?)\n            exit$",
            re.MULTILINE | re.DOTALL)
        re_giface = re.compile(
            "^(                group-interface \".+?\" create(?:\n                    description \".+?\")?)$",
            re.DOTALL | re.MULTILINE)
        re_ifaces = re.compile("^(            interface .+?)\n            exit$", re.DOTALL | re.MULTILINE)
        re_ifacename = re.compile("^\s+((?:port|lag|group-interface|interface).+?)(?: create)?$", re.MULTILINE)
        re_ifaceres = re.compile(
            "^\s+access\n            adapt-qos distribute include-egr-hash-cfg\n            per-fp-ing-queuing\n            per-fp-egr-queuing\n            per-fp-sap-instance\n        exit$",
            re.DOTALL | re.MULTILINE)
        re_ifacetype = re.compile("^\s+(port|lag|group-interface|interface).+$", re.MULTILINE)
        re_ifacenum = re.compile("^\s+\D+ (.+?)(?: create)?$", re.MULTILINE)
        re_ifacedesc = re.compile("^\s+description \"?(.+?)\"?$", re.MULTILINE)
        re_ifaceshut = re.compile("^\s+(shutdown)$", re.MULTILINE)
        re_ifaceqinq = re.compile("^\s+encap-type (dot1q|qinq)$", re.MULTILINE)
        re_ifacemtu = re.compile("^\s+mtu (\d+)$", re.MULTILINE)
        re_ifacemode = re.compile("^\s+mode (hybrid|access)$", re.MULTILINE)
        re_ifaceloop = re.compile("^\s+(loopback)$", re.MULTILINE)
        re_ifaceaddr = re.compile("^\s+address ((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
                                  "(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\S*)$", re.MULTILINE)
        re_ifaceaddrv6 = re.compile("^\s+address ("
                                    "(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|"
                                    "([0-9a-fA-F]{1,4}:){1,7}:|"
                                    "([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|"
                                    "([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|"
                                    "([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|"
                                    "([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|"
                                    "([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|"
                                    "[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|"
                                    ":((:[0-9a-fA-F]{1,4}){1,7}|:)|"
                                    "fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|"
                                    "::(ffff(:0{1,4}){0,1}:){0,1}"
                                    "((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}"
                                    "(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|"
                                    "([0-9a-fA-F]{1,4}:){1,4}:"
                                    "((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}"
                                    "(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))\S*)\s*(dad-disable\s*)?$", re.MULTILINE)
        re_ifaceaddrsec = re.compile("^\s*secondary (\S*)\s*$", re.MULTILINE)
        re_ifacesap = re.compile("^                sap (\S+) create(.*?)\n                exit$",
                                 re.DOTALL | re.MULTILINE)
        re_ifacesapi = re.compile("^                    ingress(.*?)\n                    exit$",
                                  re.DOTALL | re.MULTILINE)
        re_ifacesape = re.compile("^                    egress(.*?)\n                    exit$",
                                  re.DOTALL | re.MULTILINE)
        re_ifacesapq = re.compile("^                        qos (\d+).*$", re.MULTILINE)
        re_ifacesapf = re.compile("^                        filter (.+)$", re.MULTILINE)
        re_dhcp_server_v4 = re.compile("^                local-dhcp-server \"(.*?)\"\s*$", re.MULTILINE)
        re_dhcp_server_v6 = re.compile("^                    local-dhcp-server \"(.*?)\"\s*$", re.MULTILINE)

        li_ifaces = re_port.findall(config)
        li_ifaces += re_lag.findall(config)
        li_ifaces += re_giface.findall('\n'.join(re_siface.findall(config)))
        li_ifaces += re_giface.findall('\n'.join(re_sifacei.findall(config)))
        li_ifaces += re_giface.findall('\n'.join(re_sifacew.findall(config)))
        li_ifaces += re_ifaces.findall(config)
        for iface in li_ifaces:
            di_iface = {'cfg': iface, 'name': re_ifacename.search(iface).group(1),
                        'type': re_ifacetype.search(iface).group(1), 'num': re_ifacenum.search(iface).group(1),
                        'mode': None, 'giface': None}

            desc = re_ifacedesc.search(iface)
            if None != desc:
                di_iface['desc'] = desc.group(1)
            else:
                di_iface['desc'] = ''

            shut = re_ifaceshut.search(iface)
            if None != shut:
                di_iface['shut'] = 1
            else:
                di_iface['shut'] = 0

            addr = re_ifaceaddr.search(iface)
            addrv6 = re_ifaceaddrv6.search(iface)
            if addr:
                di_iface['addr'] = addr.group(1)
            else:
                di_iface['addr'] = None

            if addrv6:
                di_iface['addrv6'] = addrv6.group(1)
                if di_iface['addr'] is None:
                    di_iface['addr'] = di_iface['addrv6']
            else:
                di_iface['addrv6'] = None

            secondary = re_ifaceaddrsec.finditer(iface)
            di_iface['secondary'] = []
            for sec in secondary:
                di_iface['secondary'].append(sec.group(1))

            qinq = re_ifaceqinq.search(iface)
            if None != qinq and 'qinq' == qinq.group(1):
                di_iface['qinq'] = 'customer'
            else:
                di_iface['qinq'] = 'normal'

            mtu = re_ifacemtu.search(iface)
            if None != mtu:
                di_iface['mtu'] = mtu.group(1)
            else:
                di_iface['mtu'] = ''

            res_optimization = re_ifaceres.search(iface)
            if None != res_optimization:
                di_iface['res_optimization'] = 1
            else:
                di_iface['res_optimization'] = 0

            port_mode = re_ifacemode.search(iface)
            if None != port_mode:
                di_iface['port_mode'] = port_mode.group(1)
            else:
                di_iface['port_mode'] = ''

            loop = re_ifaceloop.search(iface)
            if loop:
                di_iface['type'] = 'loopback'

            if 'lag' == di_iface['type']:
                ports = re_membport.findall(iface)
                di_iface['members'] = set()
                for port in ports:
                    di_iface['members'] |= set([port])
                    ifaces['port ' + port]['lag'] = di_iface['num']

            sap = re_ifacesap.search(iface)
            if sap:
                di_iface['sap'] = sap.group(1)
                ing = re_ifacesapi.search(sap.group(2))
                eng = re_ifacesape.search(sap.group(2))
                di_iface['qos_in'] = None
                di_iface['acl_in'] = None
                di_iface['qos_out'] = None
                di_iface['acl_out'] = None
                if ing:
                    q = re_ifacesapq.search(ing.group(1))
                    f = re_ifacesapf.search(ing.group(1))
                    if q:
                        di_iface['qos_in'] = q.group(1)
                    if f:
                        di_iface['acl_in'] = f.group(1)
                if eng:
                    q = re_ifacesapq.search(eng.group(1))
                    f = re_ifacesapf.search(eng.group(1))
                    if q:
                        di_iface['qos_out'] = q.group(1)
                    if f:
                        di_iface['acl_out'] = f.group(1)
            else:
                di_iface['sap'] = None

            di_iface['dhcp_v4'] = None
            dhcp_v4 = re_dhcp_server_v4.search(iface)
            if dhcp_v4 is not None:
                di_iface['dhcp_v4'] = dhcp_v4.group(1)

            di_iface['dhcp_v6'] = None
            dhcp_v6 = re_dhcp_server_v6.search(iface)
            if dhcp_v6 is not None:
                di_iface['dhcp_v6'] = dhcp_v6.group(1)

            if 'interface' == di_iface['type']:
                di_iface['type'] = 'subinterface'

            ifaces[di_iface['name']] = di_iface
        return ifaces

    # parse DHCP pools
    def parse_dhcp_servers(config):
        result = {}
        dhcp_configs = {}
        MO = mgmt.segment.settings['MO']
        re_dhcp_server = re.compile(
            "^(?P<space>\s*)local-dhcp-server\s+\"(?P<name>\S+)\"\s+create\s*(?P<config>.*?)^(?P=space)exit",
            re.MULTILINE | re.DOTALL)
        re_pools = re.compile("^(                    pool \"(\S+?)\" create\n.+?\n                    exit)$",
                              re.MULTILINE | re.DOTALL)
        re_subnet = re.compile("^                        subnet (\S+) create$", re.MULTILINE)
        re_subnetv6 = re.compile("^                        prefix (\S+).*create\s*$", re.MULTILINE)
        re_lease = re.compile("lease-time min (\d+)")
        re_failover = re.compile("failover\s*peer\s+(?P<ip>\S*)\s+tag\s+\"(?P<tag>.*?)\"\s*"
                                 "(?P<sh>shutdown|no\s+shutdown)", re.MULTILINE | re.DOTALL)
        re_fo_ip = re.compile('10\.6\.%s\.(1|2)$' % MO, re.MULTILINE)

        re_vprn100 = re.compile("^        vprn 100 (name .+?)?customer 1 create\n(.+?)\n        exit$",
                                re.MULTILINE | re.DOTALL)

        vprn100 = '\n'.join([i[1] for i in re_vprn100.findall(config)])
        dhcp_servers = re_dhcp_server.finditer(vprn100)
        for dhcp_server in dhcp_servers:
            dhcp_name = dhcp_server.group('name')
            dhcp_conf = dhcp_server.group('config')
            if dhcp_name not in result:
                result[dhcp_name] = {}
            if dhcp_name not in dhcp_configs:
                dhcp_configs[dhcp_name] = {
                    'local': {},
                    'pools': {}
                }

            failover = re_failover.search(dhcp_conf)
            fo_ip = fo_tag = fo_sh = 'None'
            if failover is not None:
                fo_ip = failover.group('ip')
                fo_tag = failover.group('tag')
                fo_sh = failover.group('sh')
            dhcp_configs[dhcp_name]['local']['failover_ip'] = fo_ip or 'None'
            dhcp_configs[dhcp_name]['local']['failover_tag'] = fo_tag
            dhcp_configs[dhcp_name]['local']['failover_sh'] = fo_sh

            pools = re_pools.findall(dhcp_conf)
            for pool in pools:
                pool_conf = pool[0]
                pool_name = pool[1]
                subnets = re_subnet.findall(pool_conf) + re_subnetv6.findall(pool_conf)
                subs = []
                for subnet in subnets:
                    subs += [subnet]
                result[dhcp_name][pool_name] = subs
                dhcp_configs[dhcp_name]['pools'][pool_name] = {}
                lease_match = re_lease.search(pool_conf)
                if lease_match is None:
                    lease = 'None'
                else:
                    lease = lease_match.group(1)
                dhcp_configs[dhcp_name]['pools'][pool_name]['lease'] = lease
        return result, dhcp_configs

    # parse DHCP pools
    def parse_dhcp_pools_all(config):
        import re
        result = {}
        # result2 = {}
        re_pools = re.compile("^(                    pool \"(\S+?)\"(.*?)create\n.+?\n                    exit)$",
                              re.MULTILINE | re.DOTALL)
        re_vprn = re.compile("^        vprn \d+? (name .+?)?customer 1 create\n(.+?)\n        exit$",
                             re.MULTILINE | re.DOTALL)
        re_subnet_dr = re.compile("(                        subnet (\S+) create\n.+?\n                        exit)",
                                  re.MULTILINE | re.DOTALL)
        vprn = '\n'.join([i[1] for i in re_vprn.findall(config)])
        pools = re_pools.findall(vprn)
        subs2 = []
        for pool in pools:
            is_drain2 = 0
            subnets = re_subnet_dr.findall(pool[0])
            if 'drain' in pool[0]:
                is_drain = 1
                # "on pool[1]", pool[1], "have 'drain', flag", is_drain
            else:
                is_drain = 0
            if str(pool[1]) not in result:
                result[pool[1]] = is_drain
        print(result)
        print("_____________________________")
        return result

    # parse static route
    def parse_static_routes(config):
        result = {}
        re_route = re.compile(
            "^            static-route(-entry\s|\s)(\S+)(\n\s+|\s)(?:next-hop|indirect|blackhole|black-hole )?(\S+)?(\n\s+|\s)?(?: preference (\d+))?(\n\s+|\s)?(?: metric (\d+))?$",
            re.MULTILINE)

        re_vprn100 = re.compile("^        vprn 100 (name .+?)?customer 1 create\n(.+?)\n        exit$",
                                re.MULTILINE | re.DOTALL)
        vprn100 = '\n'.join([i[1] for i in re_vprn100.findall(config)])
        routes = re_route.findall(vprn100)
        for route in routes:
            result[route[1]] = {}
            result[route[1]]['next-hop'] = route[3]
            result[route[1]]['preference'] = route[5]
            result[route[1]]['metric'] = route[7]
        return result

    # ________DDS-13452
    def parse_sub_default_address(config):
        real_nets = []
        re_address = re.compile(
            '(?:address|prefix)\s+(?P<address>(?:(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\/\d+)|(?:\S*\/\d+))')
        for address_match in re_address.finditer(config):
            address = address_match.group('address')
            if ip.is_ipv4_prefix(address):
                address = ip.IPv4(address)
            else:
                address = ip.IPv6(address)
            net_address = address.first
            real_nets.append(str(net_address))
        return real_nets

    # check pools in blackhole
    def check_pools_blackhole(config, dhcp_servers, routes, dhcp_configs):
        result = {}

        re_failover_ideal = re.compile('^\s*redundancy\s+multi-chassis\s+peer\s+(\S*)\s+create', re.MULTILINE)
        failover_ideal = re_failover_ideal.search(config)
        if failover_ideal is None:
            failover_ideal = 'None'
        else:
            failover_ideal = failover_ideal.group(1)

        ideal_dhcp_data = {
            'DEFAULT-DHCP-ANYCAST': {
                'failover_ip': {'value': failover_ideal, 'code': 104021},
                'failover_tag': {'value': 'DEFAULT-DHCP-ANYCAST', 'code': 104022},
                'failover_sh': {'value': 'no shutdown', 'code': 104023},
            },
            'DEFAULT-DHCP-V6-ANYCAST': {
                'failover_ip': {'value': failover_ideal, 'code': 104021},
                'failover_tag': {'value': 'DEFAULT-DHCP-V6-ANYCAST', 'code': 104022},
                'failover_sh': {'value': 'no shutdown', 'code': 104023},
            },
        }
        ideal_pool_data = {
            'lease': {'value': '30', 'code': 104020},
        }
        dhcp_servers_pools_to_check = ['DEFAULT-DHCP-ANYCAST']
        for dhcp_server in dhcp_servers:
            if dhcp_server.upper() == 'DEFAULT-DHCP-ANYCAST':
                pools_to_exist = ['LP-CORP-01-1', 'LP-CORP-01-2', 'LP-DHCP-PRVSN', 'LP-REDIRECT-1', 'LP-REDIRECT-2',
                                  'LP-PUNLIMIT-01-1', 'LP-PUNLIMIT-01-2', 'LP-RUNLIMIT-01-1', 'LP-RUNLIMIT-01-2',
                                  'LP-REDIRECT-DHCP-1', 'LP-REDIRECT-DHCP-2']
                for pool in pools_to_exist:
                    result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 104005, result)
                    if pool not in dhcp_servers[dhcp_server]:
                        result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 104005,
                                                     "Pool %s not found in DEFAULT-DHCP-ANYCAST" % pool,
                                                     result)
                continue
            pools = dhcp_servers[dhcp_server]
            for pool in pools:
                if "LP-DENY-REASON" in pool or "LP-FAKE-POOL" in pool or "LP-REDIRECT" in pool or "LP-DHCP-RDRCT" in pool:
                    continue
                for net in pools[pool]:
                    if not ip.is_ipv4_prefix(net):
                        continue
                    result = liboba.get_war_count2(4001, result)
                    if net not in routes or 'black-hole' != routes[net]['next-hop']:
                        result = liboba.get_war_desc2(4001, "%s network from pool %s not found in static "
                                                            "routes to black-hole" % (net, pool), result)

        for dhcp_server in dhcp_configs:
            local_checks = dhcp_configs[dhcp_server]['local']
            for param in ideal_dhcp_data.get(dhcp_server, {}):
                result = liboba.get_war_count(CHK_WRNG_CNST_ALU, ideal_dhcp_data[dhcp_server][param]['code'], result)
                if local_checks[param] != ideal_dhcp_data[dhcp_server][param]['value']:
                    result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, ideal_dhcp_data[dhcp_server][param]['code'],
                                                 "[DHCP %s] Param %s = %s, should be %s."
                                                 % (dhcp_server, param, local_checks[param],
                                                    ideal_dhcp_data[dhcp_server][param]['value']), result)

            if dhcp_server not in dhcp_servers_pools_to_check:
                continue
            pools = dhcp_configs[dhcp_server]['pools']
            for pool in pools:
                pool_data = dhcp_configs[dhcp_server]['pools'][pool]
                for param in ideal_pool_data:
                    code = ideal_pool_data[param]['code']
                    ideal = ideal_pool_data[param]['value']
                    real = pool_data.get(param, 'None')
                    result = liboba.get_war_count(CHK_WRNG_CNST_ALU, code, result)
                    if ideal != real:
                        result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, code,
                                                     "[DHCP %s][POOL %s] Param %s = %s, should be %s"
                                                     % (dhcp_server, pool, param, real, ideal), result)

        result = liboba.add_descr_to_result(result, "<<<<< check DHCP pools >>>>> (%d/%d)")
        return result

    # get subscribes interface
    def parse_sifaces(config):
        re_siface = re.compile("^            subscriber-interface \"(\S+)\" create\n.+?\n            exit$",
                               re.MULTILINE | re.DOTALL)
        result = set(re_siface.findall(config))
        return result

    # parse pl
    def parse_pl(config):
        result = {}
        re_pl = re.compile(
            "^            prefix-list \"(PL-GENERAL|PL-GENERAL-IPV6|PL-GENERAL-VOIP|PL-[^-]+-SPEC)\"((?:\n\s+ prefix \S+ exact)+)?\n            exit$",
            re.MULTILINE | re.DOTALL)
        re_pr = re.compile("^\s+ prefix (\S+) exact$", re.MULTILINE)
        pls = re_pl.findall(config)
        for pl in pls:
            if not pl[0] in result:
                result[pl[0]] = []
            result[pl[0]] += re_pr.findall(pl[1])
        return result

    # parse PL-GENERAL-SPEC
    def parse_pl_general_spec(config):
        re_pl = re.compile(
            "^            prefix-list \"PL-GENERAL-SPEC\"((?:\n\s+ prefix \S+ (?:(?:prefix-length-range [0-9]{1,2}-[0-9]{1,2})|(?:exact)))+)?\n            exit$",
            re.MULTILINE | re.DOTALL)
        re_pr = re.compile("\s+ prefix (\S+) prefix-length-range [0-9]{1,2}-([0-9]{1,2})", re.MULTILINE | re.DOTALL)
        pls = re_pl.findall(config)
        if pls:
            prs = re_pr.findall(pls[0])
            result = prs
        else:
            result = []
        return result

    # check spec in general
    def check_pl_general_spec(pls, prs_spec):
        result = {}
        result = liboba.get_war_count2(5004, result)
        if 'PL-GENERAL' not in pls:
            result = liboba.get_war_desc2(5004, "PL-GENERAL entity not found", result)
        else:
            for pr in pls['PL-GENERAL']:
                pr_contains = False
                for pr_spec in prs_spec:
                    if pr_spec[0] == pr:
                        pr_contains = True
                        result = liboba.get_war_count2(5002, result)
                        if '24' != pr_spec[1]:
                            result = liboba.get_war_desc2(5002,
                                                          "Network %s from PL-GENERAL-SPEC has wrong prefix length" % (
                                                              pr_spec[0]), result)
                result = liboba.get_war_count2(5002, result)
                if pr_contains == False:
                    result = liboba.get_war_desc2(5002,
                                                  "Network %s from PL-GENERAL not exist in PL-GENERAL-SPEC" % (pr),
                                                  result)
        result = liboba.add_descr_to_result(result, "<<<<< check PL-GENERAL-SPEC in PL-GENERAL >>>>> (%d/%d)")
        return result

    # parse all static routes
    def parse_all_static_routes(bsrs):
        result = {}
        for bsr in bsrs:
            result = dict(result.items() + parse_static_routes(bsr.config.read()).items())
        return result

    # check pools contains "drain"
    def check_pools_with_drain(config):
        result = {}
        #  "start check drain"
        pools = parse_dhcp_pools_all(config)
        for pool, is_drain in pools.items():
            result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 104003, result)
            if is_drain == 1:
                # "pool ", pool, "is_drain = ", is_drain
                result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 104003,
                                             "pool %s contains \"drain\"" % (
                                                 pool), result)
        result = liboba.add_descr_to_result(result, "<<<<< check DHCP pools >>>>> (%d/%d)")
        return result

    # check pools other bsrs
    def check_other_bsr_pools(bsrs, dhcp_servers):
        result = {}
        for bsr in bsrs:
            odhcp_servers, odhcp_configs = parse_dhcp_servers(bsr.config.read())
            for dhcp_server in dhcp_servers:
                if dhcp_server.upper() == 'DEFAULT-DHCP-ANYCAST':
                    continue
                pools = dhcp_servers[dhcp_server]
                for pool in pools:
                    for net in pools[pool]:
                        if not ip.is_ipv4_prefix(net):
                            continue
                        pl = ip.IPv4(net)
                        for odhcp_server in odhcp_servers:
                            if odhcp_server.upper() == 'DEFAULT-DHCP-ANYCAST':
                                continue
                            opools = odhcp_servers[odhcp_server]
                            for opool in opools:
                                for onet in opools[opool]:
                                    if not ip.is_ipv4_prefix(onet):
                                        continue
                                    opl = ip.IPv4(onet)
                                    result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 104001, result)
                                    if pl.contains(ip.IPv4(opl.first.address, "255.255.255.255")) or pl.contains(
                                            ip.IPv4(opl.last.address, "255.255.255.255")):
                                        result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 104001,
                                                                     "Pool %s (%s) contains pool %s (%s) from %s"
                                                                     % (pool, net, opool, onet, bsr.name),
                                                                     result)
            result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 104004, result)
            if 'DEFAULT-DHCP-ANYCAST' in dhcp_servers and 'DEFAULT-DHCP-ANYCAST' not in odhcp_servers:
                result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 104004,
                                             "No DEFAULT-DHCP-ANYCAST on other bsr (%s)"
                                             % bsr.name, result)
            elif 'DEFAULT-DHCP-ANYCAST' not in dhcp_servers and 'DEFAULT-DHCP-ANYCAST' in odhcp_servers:
                result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 104004,
                                             "No DEFAULT-DHCP-ANYCAST on current bsr", result)
            elif 'DEFAULT-DHCP-ANYCAST' in dhcp_servers and 'DEFAULT-DHCP-ANYCAST' in odhcp_servers:
                pools = dhcp_servers['DEFAULT-DHCP-ANYCAST']
                opools = odhcp_servers['DEFAULT-DHCP-ANYCAST']

                for diff in set(pools.keys()):
                    result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 104005, result)
                for diff in set(opools.keys()):
                    result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 104005, result)

                for diff in (set(pools.keys()) - set(opools.keys())):
                    result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 104005,
                                                 "Pool %s not found on other bsr (%s)" %
                                                 (diff, bsr.name), result)
                for diff in (set(opools.keys()) - set(pools.keys())):
                    result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 104005,
                                                 "Pool %s not found on current bsr (%s)" %
                                                 (diff, mgmt), result)
                for pool in pools:
                    if pool not in opools:
                        continue
                    nets = pools[pool]
                    onets = opools[pool]

                    for diff in set(nets):
                        result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 104006, result)
                    for diff in set(onets):
                        result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 104006, result)

                    for diff in (set(nets) - set(onets)):
                        result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 104006,
                                                     "Subnet %s not found in pool %s on other bsr (%s)" %
                                                     (diff, pool, bsr.name), result)
                    for diff in (set(onets) - set(nets)):
                        result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 104006,
                                                     "Subnet %s not found in pool %s on current bsr (%s)" %
                                                     (diff, pool, mgmt), result)
        result = liboba.add_descr_to_result(result, "<<<<< check DHCP pools from other bsr >>>>> (%d/%d)")
        return result

    # check pools other bsrs
    def check_other_bsr_static(bsrs, dhcp_servers):
        result = {}
        for bsr in bsrs:
            oroutes = parse_static_routes(bsr.config.read())
            for dhcp_server in dhcp_servers:
                pools = dhcp_servers[dhcp_server]
                for pool in pools:
                    for net in pools[pool]:
                        if not ip.is_ipv4_prefix(net):
                            continue
                        pl = ip.IPv4(net)
                        for oroute in oroutes:
                            if not ip.is_ipv4_prefix(oroute):
                                continue
                            opl = ip.IPv4(oroute)
                            result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 104002, result)
                            if pl.contains(opl):
                                result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 104002,
                                                             "Pool %s (%s) contains static route %s from %s" % (
                                                                 pool, net, oroute, bsr.name), result)
        result = liboba.add_descr_to_result(result, "<<<<< check static routes from other bsr >>>>> (%d/%d)")
        return result

    # check subscribers interface
    def check_sifaces(sifaces):
        SIFS = (
            "DEFAULT", "IPoE", "DEFAULT-WIFI-DHCP", "MANAGE-MONITORING-DEVICE", "KTV-OPTICAL-RECEIVERS", "MM-SERVERS",
            "YOTA_HOTSPOT_WEB", "YOTA_HOTSPOT_WPA", "ROSTELEKOM", "TRUSTED-HOLDING", "ARPHOST", "DHCP-CLIENTS",
            "UPRAVLYAYUSHCHAYA-KOMPANIYA", " Wi-Fi_GCWN_112", "CAMERAS", "ACCESS-ENFORTA", "IOT-BS",
            "DEFAULT-IPOE-DHCP", "DOMOFON", "VOIP-CPE-ENFORTA", "SUB-DEFAULT", "TELEMIR-SERVERS",
            "WIFI-ZEROTOUCH-MGMT", "WIFI-POINTS", "CTRL-DEVICES"
        )
        result = {}

        for siface in sifaces:
            result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 100003, result)
            if not siface in SIFS:
                result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 100003, "subscriber-interface %s not kb" % siface,
                                             result)
        result = liboba.add_descr_to_result(result, "<<<<< check subscriber-interface >>>>> (%d/%d)")
        return result

    # get groupinterface
    def parse_gifaces(config, ifaces):
        # print(ifaces.keys())
        result = {}
        re_siface = re.compile("^            subscriber-interface \"DEFAULT\" create\n(.+?)\n            exit$",
                               re.MULTILINE | re.DOTALL)
        re_sifacei = re.compile("^            subscriber-interface \"IPoE\" create\n(.+?)\n            exit$",
                                re.MULTILINE | re.DOTALL)
        re_sifacew = re.compile(
            "^            subscriber-interface \"DEFAULT-WIFI-DHCP\" create\n(.+?)\n            exit$",
            re.MULTILINE | re.DOTALL)
        re_giface = re.compile("^                group-interface \"(.+?)\" create(.*?)\n                exit$",
                               re.MULTILINE | re.DOTALL)
        re_sap = re.compile("^                    sap (\S*)-(\d+):(\d+\.?\d*) create(.*?)\n                    exit$",
                            re.MULTILINE | re.DOTALL)
        re_vpls1 = re.compile("^        vpls 1 (?:name .+?)?customer 1 create\n(.+?)\n        exit$",
                              re.MULTILINE | re.DOTALL)

        re_vprn100 = re.compile("^        vprn 100 (name .+?)?customer 1 create\n(.+?)\n        exit$",
                                re.MULTILINE | re.DOTALL)
        vprn100 = '\n'.join([i[1] for i in re_vprn100.findall(config)])

        # ----------------
        re_vprn120 = re.compile("^        vprn 120 customer 1 create\n(.+?)\n        exit$", re.MULTILINE | re.DOTALL)
        vprn120 = '\n'.join(re_vprn120.findall(config))
        # ----------------

        vprn120 = '\n'.join(re_vprn120.findall(config))
        vpls1 = re_vpls1.findall(config)
        siface = '\n'.join(re_siface.findall(vprn100))
        siface += '\n'.join(re_sifacei.findall(vprn100))
        siface += '\n'.join(re_sifacew.findall(vprn120))
        gifaces = re_giface.findall(siface)
        r, ifaces2 = liboba.check_ifacedesc(parse_interfaces(config))
        for giface in gifaces:
            lag = None
            lag_type = None
            if not giface[0] in result:
                result[giface[0]] = {}
                result[giface[0]]['saps'] = set()
                result[giface[0]]['cfg'] = ''
                result[giface[0]]['lag'] = None
            result[giface[0]]['cfg'] += giface[1]
            lsaps = re_sap.findall(giface[1])
            if lsaps:
                saps = set(s[2] for s in lsaps if not '                        shutdown' in s[3])
                result[giface[0]]['saps'] |= saps
                lag_type = lsaps[0][0]
                lag = lsaps[0][1]
            if vpls1:
                re_msap = re.compile(
                    "^            sap (\S*)-(\d+):(\d+\.?\d*) capture-sap create\n                description \"%s\"\n.+?\n            exit$" %
                    giface[0], re.MULTILINE | re.DOTALL)
                re_msap2 = re.compile(
                    "^            sap (\S*)-(\d+):(\d+\.?\d*) capture-sap create\n(?:                cpu-protection 100 mac-monitoring\n)?                trigger-packet (?:dhcp pppoe|pppoe)\n(?:                dhcp-user-db \"LUDB-DHCP\"\n)?                pppoe-policy \"[^\"]+\"\n(?:                pppoe-user-db \"LUDB-PPPOE\"\n)?                msap-defaults\n                    group-interface \"%s\"\n.+?\n            exit$" %
                    giface[0], re.MULTILINE | re.DOTALL)
                lmsap = re_msap.findall(vpls1[0])
                lmsap += re_msap2.findall(vpls1[0])
                if lmsap:
                    msap = set(s[2] for s in lmsap)
                    result[giface[0]]['saps'] |= set(msap)
                    lag_type = lmsap[0][0]
                    lag = lmsap[0][1]
            if lag and lag_type == 'lag':
                result[giface[0]]['lag'] = lag
                result[giface[0]]['lag_type'] = lag_type
                if ifaces:
                    ifaces['lag ' + lag]['giface'] = giface[0]
                    try:
                        for port in ifaces['lag ' + lag]['members']:
                            ifaces['port ' + port]['giface'] = giface[0]
                    except Exception as ex:
                        print(ex)
            if lag and lag_type == 'pw':
                result[giface[0]]['lag'] = lag
                result[giface[0]]['lag_type'] = lag_type
            result[giface[0]]['desc_host'] = ifaces2['group-interface "' + giface[0] + '"']['desc_host']
            result[giface[0]]['desc'] = ifaces2['group-interface "' + giface[0] + '"']['desc']
        return result, ifaces

    # check other bsr gifaces
    def check_other_bsr_gifaces(bsrs, gifaces):
        result = {}

        for bsr in bsrs:
            ogifaces, ifs = parse_gifaces(bsr.config.read(), None)

            f_ogifaces = {}
            for k, v in ogifaces.iteritems():
                if 'IPOE-LAG-CORE' in k:
                    continue
                f_ogifaces[k] = v

            result = liboba.sum_results(result, check_gifaces(gifaces, f_ogifaces, bsr.name))
        result = liboba.add_descr_to_result(result, "<<<<< check group-interfaces from other bsr >>>>> (%d/%d)")
        return result

    # check gifaces
    def check_gifaces(gifaces, gifaces2, obsr):
        result = {}

        re_ifacesapg = re.compile(
            "^                    sap (\S+) create(\n                        shutdown)?(.*?)\n                    exit$",
            re.DOTALL | re.MULTILINE)
        re_srrpsap = re.compile("message-path (\S+)")
        re_srrpsapnum = re.compile(":40(?:4[0-9]|5[0-5])\.0")
        re_sapsubsla = re.compile(
            "^                        sub-sla-mgmt(.*?)\n                            no shutdown\n                        exit$",
            re.DOTALL | re.MULTILINE)
        re_sapcpuprotect = re.compile("^                        cpu-protection (\d+) mac-monitoring$",
                                      re.DOTALL | re.MULTILINE)
        re_sapantispoof = re.compile("^                        anti-spoof nh-mac$", re.DOTALL | re.MULTILINE)
        re_defslaprofile = re.compile(
            "^                            def-sla-profile \"(\S+)\"\n.*?\n                        exit$",
            re.DOTALL | re.MULTILINE)

        if '' == obsr:
            for name, iface in ifaces.iteritems():
                if 'group-interface' == iface['type']:
                    continue
                result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 107005, result)
                if 'ACCESS' == iface['desc_type'] and None == iface['giface']:
                    result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 107005,
                                                 "%s (%s) has ACCESS but has't group-interface" % (
                                                     iface['name'], iface['desc']), result)

        for name, giface in gifaces.iteritems():
            if '' == giface['cfg']:
                result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 107003, result)
                if '' == obsr:
                    result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 107003, "group-interface %s is empty" % name,
                                                 result)
                continue

            # _______DDS-13404__start___________________________________
            if ('IPOE' in str(name)) and ('HQ' not in str(name)):
                #            if 'IPOE' in str(name):
                contents_under_giface_descr = []
                re_host_connect = re.compile(
                    "(^\s+host-connectivity-verify\s+interval\s+\d+\s+action\s+remove\s+retry-count\s+\d+)",
                    re.MULTILINE | re.DOTALL)
                host_connnect = re_host_connect.search(giface['cfg'])
                result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 107011, result)
                if host_connnect is not None:
                    # "all right, host-content listed at group-interface %s" %(name)
                    pass
                else:
                    # "error, host-content not listed at group-interface %s" %(name)
                    result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 107011,
                                                 "Host-content not listed at group-interface %s" % (name), result)
                    # pass
            # ____DDS-13404__end__________________________________________________________________________________

            if set() == giface['saps']:
                result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 107006, result)
                if '' == obsr and name.upper().find('ACCESS-LAG') == -1:
                    result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 107006,
                                                 "group-interface %s has't any saps" % name, result)
                continue
            if '' == obsr:
                if giface['lag_type'] == 'lag':

                    for port in ['lag ' + giface['lag']] + ['port ' + p for p in
                                                            ifaces['lag ' + giface['lag']]['members']]:
                        if 'ACCESS' != ifaces[port]['desc_type']:
                            result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 107004, result)
                            if 'HQ_DIDS_CPE' in giface['cfg']:
                                continue
                            else:
                                result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 107004,
                                                             "%s (%s) has't ACCESS but have group-interface %s (%s)" % (
                                                                 port, ifaces[port]['desc'], name, giface['desc'],),
                                                             result)

                sapg = re_ifacesapg.findall(giface['cfg'])
                sapsrrp = re_srrpsap.findall(giface['cfg'])
                for sap in sapg:
                    sapcpuprotect = re_sapcpuprotect.findall(sap[2])
                    if sapcpuprotect and '100' == sapcpuprotect[0]:
                        continue
                    else:
                        # skip shutdown sap
                        if 'shutdown' in sap[1]:
                            continue
                        else:
                            srrpsapnum = re_srrpsapnum.findall(sap[0])
                            # skip srrp sap
                            result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 107008, result)
                            if sap[0] in sapsrrp:  # fixing https://ticket.ertelecom.ru/browse/MSA-5931
                                # if srrpsapnum and sap[0] in sapsrrp:
                                continue
                            else:
                                result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 107008,
                                                             "group-interface %s has sap %s without \"cpu-protection 100 mac-monitoring\"" % (
                                                                 name, sap[0]), result)
                """for sap in sapg:
                    sapantispoof = re_sapantispoof.findall(sap[2])
                    if sapantispoof:
                        continue
                    else:
                        # skip shutdown sap
                        if 'shutdown' in sap[1]:
                            continue
                        else:
                            srrpsapnum = re_srrpsapnum.findall(sap[0])
                            # skip srrp sap
                            if srrpsapnum and sap[0] in sapsrrp:
                                continue
                            else:
                                result, penny = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 107009,
                                                                    "group-interface %s has sap %s without \"anti-spoof nh-mac\"" % (
                                                                        name, sap[0]), result, peny)
                                e_count += 1 """

                for sap in sapg:
                    defslaprofile = re_defslaprofile.findall(sap[2])
                    if defslaprofile and 'SLA-ERROR' == defslaprofile[0]:
                        continue
                    else:
                        # skip shutdown sap
                        if 'shutdown' in sap[1]:
                            continue
                        else:
                            srrpsapnum = re_srrpsapnum.findall(sap[0])
                            # skip srrp sap
                            result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 107007, result)
                            if sap[0] in sapsrrp:  # fixing https://ticket.ertelecom.ru/browse/MSA-5931
                                # if srrpsapnum and sap[0] in sapsrrp:
                                continue
                            else:
                                result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 107007,
                                                             "group-interface %s has sap %s without def-sla-profile SLA-ERROR" % (
                                                                 name, sap[0]), result)
                for sap in sapg:
                    sapsubsla = re_sapsubsla.findall(sap[2])
                    if not sapsubsla:
                        # skip shutdown sap
                        if 'shutdown' in sap[1]:
                            continue
                        else:
                            srrpsapnum = re_srrpsapnum.findall(sap[0])
                            # skip srrp sap
                            result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 107006, result)
                            if sap[0] in sapsrrp:  # fixing https://ticket.ertelecom.ru/bro
                                # if srrpsapnum and sap[0] in sapsrrp:
                                continue
                            else:
                                result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 107006,
                                                             "group-interface %s has sap %s without sub-sla-mgmt" % (
                                                                 name, sap[0]), result)

            for name2, giface2 in gifaces2.iteritems():
                if name == name2 and '' == obsr:
                    continue
                if not ((giface['desc_host'] == giface2['desc_host'] and '' != giface['desc_host']) or (
                        name == name2 and ('' == giface['desc_host'] or '' == giface2['desc_host']))):
                    continue
                # if '*.*' in giface2['saps']:
                #                    continue
                result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 107002, result)
                for sap in giface['saps'] - giface2['saps']:
                    result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 107002, result)
                    result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 107002,
                                                 "sap %s %s (%s) not found in %s (%s) %s" % (
                                                     sap, name, giface['desc'], name2, giface2['desc'], obsr),
                                                 result)

        result = liboba.add_descr_to_result(result, "<<<<< check saps on group-interfaces %s>>>>>" % obsr + " (%d/%d)")
        return result

    # check all saps
    def check_saps():
        result = {}
        s = {}

        re_vprn100 = re.compile("^        vprn 100 (name .+?)?customer 1 create\n(.+?)\n        exit$",
                                re.MULTILINE | re.DOTALL)
        vprn100 = '\n'.join([i[1] for i in re_vprn100.findall(config)])
        saps = re.findall("^\s+sap ([^lagpw]+):\S+ create$", vprn100, re.MULTILINE)
        for sap in saps:
            if not sap in s:
                s[sap] = 0
            s[sap] += 1
        result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 108001, result)
        if {} != s:
            result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 108001, "Ports %s used for saps" % str(s), result)
            result = liboba.add_descr_to_result(result, "<<<<< check saps on physical ports >>>>> (%d/%d)")
        return result

    # parse msap-policy
    def parse_msap_policy(config):
        re_msap_policy = re.compile("^        msap-policy \"PL-MSAP-DEFAULT\" create\n(.*?)\n        exit$",
                                    re.MULTILINE | re.DOTALL)
        msap_policy = re_msap_policy.findall(config)
        if msap_policy:
            result = msap_policy[0]
        else:
            result = ''
        return result

    # check msap-policy
    def check_msap_policy(msap_policy_cfg):
        result = {}

        re_msap_policy_name = re.compile("def-sla-profile \"(\S+)\"", re.MULTILINE | re.DOTALL)
        msap_policy = re_msap_policy_name.findall(msap_policy_cfg)
        result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 116003, result)
        if len(msap_policy) > 0 and not 'SLA-ERROR' == msap_policy[0]:
            result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 116003,
                                         "def-sla-profile %s in msap-policy PL-MSAP-DEFAULT not kb" % (
                                             msap_policy[0]), result)

        result = liboba.add_descr_to_result(result,
                                            "<<<<< check msap-policy PL-MSAP-DEFAULT https://kb.ertelecom.ru/pages/viewpage.action?pageId=2785378 >>>>> (%d/%d)")
        return result

    #    def cmp_str_line(str1,str2):
    #        result=''
    #        st1=str1.split("\n")
    #        st2=str2.split("\n")
    #        for s in range(0,len(st1)):
    #            print s,st1[s]==st2[s],re.search(st1[s],str2),'"'+st1[s]+'"','"'+st2[s]+'"'
    #        return result

    def cmp_str_regexp(str1, str2, rgxp, swap=False):
        result = []
        rg1 = re.findall(rgxp, str1, re.MULTILINE | re.DOTALL)
        rg2 = re.findall(rgxp, str2, re.MULTILINE | re.DOTALL)
        for r1 in rg1:
            f = False
            for r2 in rg2:
                if swap:
                    rr1 = r2
                    rr2 = r1
                else:
                    rr1 = r1
                    rr2 = r2
                if re.search(rr1, rr2, re.MULTILINE | re.DOTALL):
                    f = True
                    break
            if not f:
                result += [str.strip(r1.split('\n')[0])]
        return result

    def check_qos_sap_ineg(config, result, iptv=False):
        qqq = '(?:                entry \S+ create.*?\n                exit)|(?:\(                entry \S+ create.*?\n                exit\)\?)|(?:            fc \S+ create.*?\n            exit)|(?:            policer \d+ create.*?\n            exit)|(?:            queue \d+ (?:profile-mode |multipoint )?create.*?\n            exit)'
        qos_sap_list = const.ALU_NEWQOS_SAP
        # int(qos_sap_list)

        errnumb = 113004
        # qos_sap_list = const.ALU_QOS600_SAP
        # errnumb = 130014
        # if not iptv:
        #    return result
        if iptv:
            qos_sap_list = const.ALU_QOS600_SAP
            errnumb = 130014

        for qos_sap in qos_sap_list:
            if not re.search(qos_sap[0], config, re.MULTILINE | re.DOTALL):
                f = False
                qos = qos_sap[0].split("\n")

                # kostyl' for MSA-6040
                if qos_sap[1] == 'qos 300 ingress':
                    qos_full = qos_sap[0]
                    re_to_exception = re.compile('(^(?P<space>\s+)entry\s+5\d\d\s+create.*?^(?P=space)exit\n)',
                                                 re.MULTILINE | re.DOTALL)
                    strs_to_exception = re_to_exception.finditer(qos_sap[0])
                    if strs_to_exception != []:
                        for str_to_exception in strs_to_exception:
                            qos_full = qos_full.replace(str_to_exception.group(0), '')
                    qos = qos_full.split("\n")
                    re_qos = '^(%s.+?\n%s)$' % (qos[0], qos[len(qos) - 1])
                    try:
                        cfg_qos_new = (re.search(re_qos, config, re.MULTILINE | re.DOTALL)).group(0)
                        strs_to_exception_cfg = re_to_exception.finditer(cfg_qos_new)
                        if strs_to_exception_cfg != []:
                            for str_to_exception in strs_to_exception_cfg:
                                cfg_qos_new = cfg_qos_new.replace(str_to_exception.group(0), '')
                        cfg_qos = [cfg_qos_new]
                    except:
                        cfg_qos = False
                    if not cfg_qos:
                        cfg_qos = ['']
                    r = cmp_str_regexp(qos_full, cfg_qos[0], qqq)
                    r_1 = cmp_str_regexp(cfg_qos[0], qos_full, qqq, True)
                else:
                    qos = qos_sap[0].split("\n")
                    re_qos = '^(%s.+?\n%s)$' % (qos[0], qos[len(qos) - 1])
                    cfg_qos = re.findall(re_qos, config, re.MULTILINE | re.DOTALL)
                    if not cfg_qos:
                        cfg_qos = ['']
                    r = cmp_str_regexp(qos_sap[0], cfg_qos[0], qqq)
                    r_1 = cmp_str_regexp(cfg_qos[0], qos_sap[0], qqq, True)

                result = liboba.get_war_count(CHK_WRNG_CNST_ALU, errnumb, result)
                if r:
                    result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, errnumb,
                                                 "%s %s has't %s kb" % (mgmt.name, qos_sap[1], r), result)
                    f = True
                r = cmp_str_regexp(cfg_qos[0], qos_sap[0], qqq, True)
                result = liboba.get_war_count(CHK_WRNG_CNST_ALU, errnumb, result)
                if r:
                    result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, errnumb,
                                                 "%s has %s not kb 11" % (qos_sap[1], r), result)
                    f = True
                result = liboba.get_war_count(CHK_WRNG_CNST_ALU, errnumb, result)
                if not f:
                    result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, errnumb, "%s not kb" % (qos_sap[1]),
                                                 result)
        return result

    def check_qos(config, ifaces):
        result = {}

        def check_saps(ifaces, result):
            for iface in ifaces.itervalues():
                if iface['sap']:
                    result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 113001, result)
                    if not iface['qos_in'] or not iface['qos_out']:
                        result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 113001,
                                                     "%s (desc %s) sap %s has't qos" % (
                                                         iface['name'], iface['desc'], iface['sap']), result)
            return result

        result = check_saps(ifaces, result)
        result = check_qos_sap_ineg(config, result)
        result = liboba.add_descr_to_result(result, "<<<<< check qos https://kb.ertelecom.ru/x/4AMuAQ >>>>> (%d/%d)")
        return result

    def get_skip_filter_check_ifaces(struct_config, bras_name):
        """
        MSA-6059
        Get interfaces that in vprn's with numbers 4xxxx and 7xxxx
        This interfaces will be skipped in filters check.
        Designed to use with check_filters().
        Look at https://ticket.ertelecom.ru/browse/MSA-6059 for more details.

        Parameters
        ----------
        struct_config: dict
            BRAS config structurized by libolga.main_1()
        bras_name: str
            From wich BRAS get interfaces.

        Returns
        -------
        list[str]
            List of vprn's interfaces names.
        """
        skip_filter_check = []
        for vprn, vprn_cont in struct_config[bras_name]['echo "Service Configuration"']['service']['vprns'].items():
            vprn_num = int(vprn)
            if vprn_num in range(40000, 50000) or vprn_num in range(70000, 80000):
                skip_filter_check.extend(vprn_cont['setap_content']['interfaces'].keys())
        return skip_filter_check

    def check_filters(config, ifaces, ignore):
        """
        This docstring contains only MSA-6059 'ignore' new parameter definition.
        Look at https://ticket.ertelecom.ru/browse/MSA-6059 for more details.

        Parameters
        ----------
        config: str
            Device configuration.
        ifaces:dict
            Result of parse_interfaces()
        ignore: list[str]
            Result of get_skip_filter_check_ifaces()

        Returns
        -------
        dict[dict]
            Returns standart liboba result.
        """
        result = {}

        int_vprn600 = []
        re_vprn600 = re.compile("^        vprn 600 customer 1 create\n(.+?)\n        exit$", re.MULTILINE | re.DOTALL)
        re_int_vprn600 = re.compile('           (interface .+) create$', re.MULTILINE)
        vprn600 = re_vprn600.findall(config)
        if vprn600:
            int_vprn600 = re_int_vprn600.findall(vprn600[0])
        for iface in ifaces.itervalues():
            # MSA-6059
            # Because `ifaces` stores name in dirty-form, striping `interface ` pref and quotes
            # to get clear interface name.
            ifname = iface['name'].lstrip('interface ').strip('"')
            # And skip it, if in MSA-6059 defined ignoring range.
            if ifname in ignore:
                continue
            if iface['addr']:
                if 'loopback' == iface['type']:
                    continue
                if iface['name'] in int_vprn600:
                    continue
                if iface['sap'] and (iface['acl_in'] or iface['acl_out']):
                    continue
                if liboba.pl_cont_pr(
                        ['172.20.0.0/28', '172.20.0.16/28', '172.20.0.32/28', '172.20.0.48/28', '172.20.0.64/28'],
                        iface['addr']):
                    continue
                if 'ERTELECOM-VRF3' in iface['desc']:
                    continue
                if 'ERTELECOM-VRF-BILLING' in iface['desc']:
                    continue
                if 'BB-VRF-BILLING' in iface['desc']:
                    continue
                if 'UPSTREAM-MEGAFON' in iface['desc']:
                    continue
                if 'ERTELECOM-VRF_VOIP' in iface['desc']:
                    continue
                if 'BB-CCTV' in iface['name']:
                    continue
                if 'LP-DENY-REASON' in iface['desc']:
                    continue
                result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 111009, result)
                if liboba.pl_cont_pr(['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'], iface['addr']) or 'MGM' in \
                        iface['desc'] or 'MGN' in iface['desc']:
                    result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 111009, "%s (desc %s) sap %s has't filter" % (
                        iface['name'], iface['desc'], iface['sap']), result)

        result = liboba.add_descr_to_result(result, "<<<<< check filters >>>>> (%d/%d)")
        return result

    def check_mtu(ifaces):
        result = {}

        for iface in ifaces.itervalues():
            if iface['qinq'] == 'customer' and 'port' in iface['name'] and 'access' == iface['port_mode']:
                result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 116001, result)
                if '9212' != iface['mtu']:
                    result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 116001,
                                                 "%s (desc %s) has wrong mtu" % (iface['name'], iface['desc']),
                                                 result)

        result = liboba.add_descr_to_result(result,
                                            "<<<<< check mtu https://kb.ertelecom.ru/pages/viewpage.action?pageId=122585746 >>>>> (%d/%d)")
        return result

    def check_mda_resource_optimization(ifaces):
        result = {}
        for iface in ifaces.itervalues():
            if 'lag' in iface['name'] and 'access' == iface['port_mode']:
                result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 116002, result)
                if 1 != iface['res_optimization']:
                    result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 116002,
                                                 "%s (desc %s) per-fp-ing-queuing and per-fp-egr-queuing not enabled" % (
                                                     iface['name'], iface['desc']), result)
        result = liboba.add_descr_to_result(result,
                                            "<<<<< check mda sap resource optimizations https://kb.ertelecom.ru/pages/viewpage.action?pageId=122585746 >>>>> (%d/%d)")
        return result

    def check_cpm_filter(config):
        result = {}
        warning_damage = 0

        rx_filters_cpm = re.compile(
            '^            cpm-filter\n                ip-filter\n                    entry.*?^                exit',
            re.DOTALL | re.MULTILINE)
        rx_filters_cpm_routers = re.compile(
            '^            cpm-filter\n                ip-filter\n                    no shutdown.*?^                exit',
            re.DOTALL | re.MULTILINE)
        rx_entry = re.compile('^                    entry\s+(\d+).*?^                    exit',
                              re.DOTALL | re.MULTILINE)

        optional_entries = [x for x in range(13, 19)]
        optional_entries += [x for x in range(31, 35)]
        optional_entries += [x for x in range(41, 45)]
        optional_entries += [x for x in range(51, 55)]
        optional_entries += [x for x in range(60, 99)]
        optional_entries += [x for x in range(155, 170)]
        optional_entries += [x for x in range(2034, 2040)]

        checks = [
            [rx_filters_cpm, const.REQ_FILTER_ENTRIES_ALU, 'Cpm Hw Filters'],
            [rx_filters_cpm_routers, const.REQ_FILTER_ENTRIES_ALU_CPM_ROUTER, 'Cpm Router']
        ]

        for check in checks:
            exist_entries = {}
            rx_filters = check[0]
            data_const = check[1]
            conf_part = check[2]

            item = rx_filters.search(config)
            context = item.group()

            for entry in rx_entry.finditer(context):
                number = entry.group(1)
                exist_entries[number] = entry.group()

            req_entries_keys = data_const.keys()
            exist_entries_keys = exist_entries.keys()

            not_found_entries = set(req_entries_keys) - set(exist_entries_keys)
            exessive_entries = set(exist_entries_keys) - set(req_entries_keys)

            for key in req_entries_keys:
                result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 107010, result)
            for key in exist_entries_keys:
                result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 107010, result)

            # print req_entries_keys
            # print exist_entries_keys
            # print not_found_entries
            # print exessive_entries
            for key in not_found_entries:
                if int(key) in optional_entries:
                    continue
                result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 107010,
                                             "WARNING: Not found entry %s in %s" % (key, conf_part), result)
            for key in exessive_entries:
                if int(key) in optional_entries:
                    continue
                result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 107010,
                                             "WARNING: Found excessive entry %s in %s" % (key, conf_part), result)

            for e_key in exist_entries_keys:
                tmp_key = e_key
                if int(e_key) in optional_entries:
                    e_key = int(e_key)
                    while e_key in optional_entries:
                        e_key -= 1
                    e_key += 1
                    e_key = str(e_key)
                if e_key in data_const.keys():
                    entyre_cnontext = exist_entries[tmp_key]
                    etalon_context = data_const[e_key]
                    cpm_regex = re.compile(etalon_context)
                    result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 107010, result)
                    if not cpm_regex.findall(entyre_cnontext):
                        result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 107010,
                                                     "WARNING: Context of entry %s in %s is invalid" % (
                                                         tmp_key, conf_part), result)

        result = liboba.add_descr_to_result(result,
                                            "<<<<< check cmp-filter kb: https://kb.ertelecom.ru/pages/viewpage.action?pageId=114362487 >>>>> (%d/%d)")
        return result

    # check_ludb
    def check_ludb(config):
        rx_ludb_ppoe = re.compile(r'local-user-db "LUDB-PPPOE" create\n            ppp.*?\n        exit',
                                  flags=re.DOTALL | re.MULTILINE)
        rx_ludb_dhcp = re.compile(r'local-user-db "LUDB-DHCP" create\n            description.*?\n        exit',
                                  flags=re.DOTALL | re.MULTILINE)
        rx_host = re.compile(r'                host "(.*?)" create\n.*?\n                exit',
                             flags=re.DOTALL | re.MULTILINE)

        def check_ludb_ppoe(config):
            result = {}
            match = rx_ludb_ppoe.search(config)
            result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 140001, result)
            if not match:
                return liboba.get_war_desc(CHK_WRNG_CNST_ALU, 140001, 'local-user-db "LUDB-PPPOE" not found in config',
                                           result)
            match = match.group()
            result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 140002, result)
            if not const.LUDB_PPPOE_CONTEXT in match:
                return liboba.get_war_desc(CHK_WRNG_CNST_ALU, 140002, 'local-user-db "LUDB-PPPOE" context is incorrect',
                                           result)
            return result

        def check_ludb_dhcp(config):
            result = {}
            match = rx_ludb_dhcp.search(config)
            result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 140001, result)
            if not match:
                return liboba.get_war_desc(CHK_WRNG_CNST_ALU, 140001, 'local-user-db "LUDB-DHCP" not found in config',
                                           result)
            match = match.group()
            hosts = ''.join([v for x, v in sorted(const.LUDB_DHCP_HOSTS.iteritems())])
            result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 140002, result)
            if const.LUDB_DHCP_CONTEXT % (hosts) in match:
                return {}

            result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 140002, 'local-user-db "LUDB-DHCP" context is incorrect',
                                         result)
            ex_hosts = [(host.group(1), host.group()) for host in rx_host.finditer(match)]
            ex_hosts = dict(ex_hosts)
            req_hosts_keys = set(const.LUDB_DHCP_HOSTS.keys())
            ex_hosts_keys = set(ex_hosts.keys())

            for key in req_hosts_keys:
                result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 140003, result)
            for key in req_hosts_keys:
                result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 140004, result)
            for key in req_hosts_keys - ex_hosts_keys:
                result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 140003,
                                             'local-user-db "LUDB-DHCP": host "%s" not found' % key, result)
            for key in ex_hosts_keys - req_hosts_keys:
                result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 140004,
                                             'local-user-db "LUDB-DHCP": host "%s" is excessive' % key, result)
            for key in ex_hosts:
                result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 140005, result)
                if key in req_hosts_keys and not ex_hosts[key] in const.LUDB_DHCP_HOSTS[key]:
                    result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 140005,
                                                 'local-user-db "LUDB-DHCP": host "%s" context is incorrect' % key,
                                                 result)
            return result

        result = check_ludb_ppoe(config)
        r = check_ludb_dhcp(config)
        result = liboba.sum_results(result, r)

        result = liboba.add_descr_to_result(result,
                                            "<<<<< check  local-user-db  kb: https://kb.ertelecom.ru/pages/viewpage.action?pageId=76157978 >>>>> (%d/%d)")
        return result

    # check pado policy
    def check_pado_polices(config):
        result = {}

        rx_sap = re.compile('^            sap (lag-\d+):\*\.\* capture-sap create.*?\n            exit$',
                            re.MULTILINE | re.DOTALL)
        rx_sap_policy = re.compile('^                pppoe-policy "(.*?)"$', re.MULTILINE | re.DOTALL)
        rx_group_interface = re.compile('^                    group-interface "(.*?)"$', re.MULTILINE | re.DOTALL)

        rx_giface = re.compile(
            '^                group-interface "(\S*?-LAG-\d+)" create$\n.*?\n                    exit\n                exit$',
            re.DOTALL | re.MULTILINE)
        rx_giface_policy = re.compile('^                    pppoe\n                        policy "(.*?)"$',
                                      re.MULTILINE | re.DOTALL)

        saps_d = []
        saps = rx_sap.finditer(config)
        for item in saps:
            context = item.group()
            name = item.group(1).upper()
            if not name:
                continue
            policy = rx_sap_policy.search(context)
            if not policy:
                continue
            policy = policy.group(1)
            gi = rx_group_interface.search(context)
            if not gi:
                saps_d += [(name, ('ACCESS-' + name.upper(), policy))]
                saps_d += [(name, ('DEFAULT-' + name.upper(), policy))]
            else:
                gi = gi.group(1)
                saps_d += [(name, (gi, policy))]

        # saps_d = dict(saps_d)
        gifaces_d = []
        gifaces = rx_giface.finditer(config)
        for item in gifaces:
            context = item.group()
            name = item.group(1)
            policy = rx_giface_policy.search(context)
            if not policy:
                continue
            policy = policy.group(1)
            gifaces_d += [(name, policy)]
        gifaces_d = dict(gifaces_d)

        # for k, v in saps_d.iteritems():
        for sap in saps_d:
            k = sap[0]
            v = sap[1]
            giface = None
            try:
                giface = gifaces_d[v[0]]
            except Exception:
                giface = None
            if not giface:
                continue
            result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 141001, result)
            if v[1] != giface:
                result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 141001,
                                             'Policies are differ for %s: vpls 1 %s ;group-interface %s: %s' % (
                                                 k, v[1], v[0], giface), result)

        result = liboba.add_descr_to_result(result,
                                            "<<<<< check pado policy kb: https://kb.ertelecom.ru/pages/viewpage.action?pageId=2785378 >>>>> (%d/%d)")
        return result

    # check ip-filter 300
    def check_ipfilter(config):
        rx_filter = re.compile(r'^        ip-filter 300 create\n.*?^        exit', flags=re.DOTALL | re.MULTILINE)
        rx_filter_description = re.compile(r'^            description \"(.*?)\"( *)$', flags=re.DOTALL | re.MULTILINE)
        rx_entry = re.compile(r'^            entry (\d+).*?^            exit', flags=re.DOTALL | re.MULTILINE)

        result = {}

        def check_ipfilter_context(config):
            result = {}
            match = rx_filter.search(config)
            result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 142001, result)
            if not match:
                return liboba.get_war_desc(CHK_WRNG_CNST_ALU, 142001, 'ip-filter 300 not found in config', result)

            match = match.group()
            desc_match = rx_filter_description.search(match)
            result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 142002, result)
            if not desc_match:
                result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 142002, 'ip-filter 300 description not found', result)
            else:
                desc_match = desc_match.group(1)
                result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 142003, result)
                if desc_match != "VOIP ADAPTERS FILTER":
                    result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 142003, 'ip-filter 300 description incorrect',
                                                 result)

            ex_hosts = [(host.group(1), host.group()) for host in rx_entry.finditer(match)]
            ex_hosts = dict(ex_hosts)
            req_hosts_keys = set(const.FILTER_300_V14_ENTRIES.keys())
            ex_hosts_keys = set(ex_hosts.keys())

            for key in req_hosts_keys:
                result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 142004, result)
            for key in ex_hosts_keys:
                result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 142005, result)

            for key in req_hosts_keys - ex_hosts_keys:
                result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 142004, 'ip-filter 300: entry %s not found' % (key),
                                             result)
            for key in ex_hosts_keys - req_hosts_keys:
                result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 142005, 'ip-filter 300: entry %s is excessive' % (key),
                                             result)
            for key in ex_hosts:
                if key in req_hosts_keys:
                    result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 142006, result)
                    match = re.search(const.FILTER_300_V14_ENTRIES[key], ex_hosts[key], re.DOTALL | re.MULTILINE)
                    if match is None:
                        result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 142006,
                                                     'ip-filter 300: entry %s context is incorrect' % (key), result)
            return result

        result = check_ipfilter_context(config)
        result = liboba.add_descr_to_result(result,
                                            "<<<<< check  ip-filter 300 kb: https://kb.ertelecom.ru/pages/viewpage.action?pageId=2785413#id-3.4.Реализацияуслуги\"Телефония\"-Конфигурация.1 >>>>> (%d/%d)")
        return result

    # check ip-filter 90
    def check_filter_90(config):
        result = {}
        warning_damage = 0

        rx_filter = re.compile('^        ip-filter 90 create\n.*?^        exit', re.DOTALL | re.MULTILINE)
        rx_entry = re.compile('^            entry (\d+).*?^            exit', re.DOTALL | re.MULTILINE)

        exist_entries = {}

        filter_context = rx_filter.search(config)
        result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 143001, result)
        if not filter_context:
            result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 143001, 'Filter 90 not found', result)

        if filter_context:
            context = filter_context.group()

            for entry in rx_entry.finditer(context):
                number = entry.group(1)
                exist_entries[number] = entry.group()

            req_entries_keys = const.REQ_FILTER_90.keys()
            exist_entries_keys = exist_entries.keys()

            not_found_entries = set(req_entries_keys) - set(exist_entries_keys)
            exessive_entries = set(exist_entries_keys) - set(req_entries_keys)

            for key in req_entries_keys:
                result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 143002, result)
            for key in exist_entries_keys:
                result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 143003, result)

            for key in not_found_entries:
                result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 143002, 'Not found entry %s' % (key), result)

            for key in exessive_entries:
                result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 143003, 'Excessive entry %s' % (key), result)

            for e_key in exist_entries_keys:
                if e_key in const.REQ_FILTER_90.keys():
                    entyre_cnontext = exist_entries[e_key]
                    etalon_context = const.REQ_FILTER_90[e_key]
                    if isinstance(etalon_context, tuple):
                        etalon_context = ''.join(etalon_context)
                    result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 143004, result)
                    if re.match(entyre_cnontext, etalon_context, re.DOTALL | re.MULTILINE) is None:
                        result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 143004,
                                                     'Context of entry %s is invalid' % (e_key), result)
        result = liboba.add_descr_to_result(result,
                                            "<<<<< check filter-90 kb: https://kb.ertelecom.ru/pages/viewpage.action?pageId=5505350#id-2.3.1.3.НастройкимаршрутизаторовALu7750SR-2.3.1.3.7.7ФильтрвсторонуBOFинтерфейсов. >>>>> (%d/%d)")
        return result

    # change for MSA-5985
    def check_double_bras(dlocal_d_config, main_bras_name, double_bras_name):
        print(main_bras_name, double_bras_name)
        result = {}

        def get_vpls_dict(d_vplss):
            # re_vpls = re.compile("^(        vpls .+?)\n        exit$", re.MULTILINE | re.DOTALL)
            # re_numvpls = re.compile("^        vpls (\w+)?")
            ## re_vpls_cust = re.compile("(customer .+?) create")
            re_vpls_desc = re.compile("description \"(.+?)\"")
            re_shut_vpls = re.compile("^            (shutdown)$", re.MULTILINE | re.DOTALL)
            re_mesh = re.compile("^            mesh-sdp \d*?:(\d*?)\s", re.MULTILINE | re.DOTALL)
            re_sapconf = re.compile("^            (sap .+?)\n            exit$", re.MULTILINE | re.DOTALL)
            # re_sapnum = re.compile("^(sap .+?) create")
            re_sapnum = re.compile("^(sap .+?)\s")
            re_mtu = re.compile(r"^\s*service-mtu (?P<mtu>\d+)", re.MULTILINE)
            re_mesh_no_sh = re.compile("^            mesh-sdp \d*?:(\d*?)\screate\s*no shutdown",
                                       re.MULTILINE | re.DOTALL)
            re_bgp_vpls = re.compile("^            bgp-vpls.+?\sve-id (\d+).*?\n            exit$",
                                     re.MULTILINE | re.DOTALL)
            re_monitor_oper_group = re.compile(
                r"            bgp$.*?monitor-oper-group \"VRRP-3\".*?\n            exit$", re.MULTILINE | re.DOTALL)
            re_stp_priority = re.compile("(^(?P<space>\s+)stp\s(.+?)^(?P=space)exit$)", re.MULTILINE | re.DOTALL)
            # vplses = re_vpls.findall(cnfg)
            vpls_conf = {}
            # for vpls in vplses:
            for num_vpls, vpls_content in d_vplss.items():
                declare_content = vpls_content.get('declare_content', {})
                vpls = declare_content.get('content', '')
                if vpls == '':
                    print("ERROR ON vpls=%s" % (str(num_vpls)))
                    continue
                # numvpls = re_numvpls.findall(vpls)[0]  # nomer vpls
                numvpls = num_vpls
                descvpls = re_vpls_desc.findall(vpls)
                descvpls = declare_content['description']
                # descvpls = re_vpls_desc.findall(vpls)
                # custvpls= re_vpls_cust.findall(vpls)
                sapconf = re_sapconf.findall(vpls)
                saps = []
                vpls_conf[numvpls] = []
                # 0 - saps
                for sap in sapconf:
                    sapnum = re_sapnum.findall(sap)[0]
                    saps.append(sapnum)
                vpls_conf[numvpls].append(saps)

                # 1 - mesh found (True|False)
                mesh = re_mesh.findall(vpls)
                if mesh == []:
                    vpls_conf[numvpls].append(None)
                else:
                    vpls_conf[numvpls].append(mesh[0] == numvpls)

                # 2 - vpls no shutdown
                if not re_shut_vpls.search(vpls):
                    vpls_conf[numvpls].append(True)
                else:
                    vpls_conf[numvpls].append(False)

                # 3 - vpls descr
                if descvpls == []:
                    vpls_conf[numvpls].append('')
                else:
                    # vpls_conf[numvpls].append(descvpls[0])
                    vpls_conf[numvpls].append(descvpls)

                # 4 - mtu
                mtu_str = re_mtu.search(vpls)
                if mtu_str is not None:
                    mtu = mtu_str.group('mtu')
                    vpls_conf[numvpls].append(mtu)
                else:
                    vpls_conf[numvpls].append('0')

                # 5 - mesh no shutdown
                mesh_no_sh = re_mesh_no_sh.search(vpls)
                if mesh_no_sh is not None:
                    vpls_conf[numvpls].append(True)
                else:
                    vpls_conf[numvpls].append(False)

                # 6 - bgp-vpls id
                ve_id = re_bgp_vpls.search(vpls)
                if ve_id is not None:
                    ve_id = ve_id.group(1)
                else:
                    ve_id = 'None'
                vpls_conf[numvpls].append(ve_id)

                # 7 - re_monitor_oper_group
                monitor_oper_group = re_monitor_oper_group.search(vpls)
                if monitor_oper_group is not None:
                    vpls_conf[numvpls].append(True)
                else:
                    vpls_conf[numvpls].append(False)

                    # 8
                    # _____DDS-13311__parse_stp_from_description
                if numvpls == '2':
                    descr_stp = re_stp_priority.search(vpls)
                    if descr_stp is not None:
                        re_prior = re.compile("(^\s+priority\s(\d+))", re.DOTALL | re.MULTILINE)
                        prior = re_prior.search((descr_stp.group(3)))
                        if prior is not None:
                            vpls_conf[numvpls].append(str(prior.group(2)))
                        else:
                            vpls_conf[numvpls].append('0')
                    else:
                        vpls_conf[numvpls].append('STP is None')
                else:
                    vpls_conf[numvpls].append('')

            return vpls_conf

        def get_srrp(d_vprns):
            srrp_dict = {}
            re_srrp = re.compile("^(?P<space>\s*)srrp\s+(?P<num>\d+)\s+create\s*(?P<config>.*?)(?P=space)exit",
                                 re.MULTILINE | re.DOTALL)
            re_priority = re.compile("priority\s+(?P<priority>\d+)")

            for num_vprn, d_vprn in d_vprns.items():
                setap_content = d_vprn.get('setap_content', {})
                vprn_content = setap_content.get('content', '')
                if vprn_content == '':
                    print("setap_content has not key vprn_content ")
                    continue
                # for srrp in re_srrp.finditer(cnfg):
                for srrp in re_srrp.finditer(vprn_content):
                    srrp_num = srrp.group('num')
                    srrp_conf = srrp.group('config')
                    priority_item = re_priority.search(srrp_conf)
                    priority = priority_item.group('priority') if priority_item is not None else 'None'
                    srrp_dict[srrp_num] = priority

            return srrp_dict

        # current_bras = get_vpls_dict(config)
        d_vplss = dlocal_d_config[main_bras_name]['echo "Service Configuration"']['service']['vplss']
        current_bras = get_vpls_dict(d_vplss)

        cur_nocheck = []

        for vpls in current_bras:
            if 'NOCHECK' in current_bras[vpls][3].upper():
                cur_nocheck.append(vpls)
            result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 108003, result)
            if int(current_bras[vpls][4]) > 9100:
                result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 108003,
                                             "[%s][vpls %s] MTU = %s, should be le 9100" % (
                                                 str(main_bras_name), str(vpls), str(current_bras[vpls][4])),
                                             result)

        result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 108011, result)
        if len(cur_nocheck) > 10:
            result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 108011,
                                         '[%s] the number of NOCHECK vpls is >10.' % (str(main_bras_name)), result)

        re_policy_statement = re.compile("(^(?P<space>\s+)policy-statement \"TO-BBR-VPN\"\s(.*?)^(?P=space)exit$)",
                                         re.DOTALL | re.MULTILINE)
        # policy_statent = re_policy_statement.search(config)
        policy_statent = re_policy_statement.search(dlocal_d_config[main_bras_name]['echo "Policy Configuration"'])

        responce_entry = {}
        if policy_statent is not None:
            required_entry = [100, 110, 200, 210]
            for entry in required_entry:
                re_inside_entry_ps = re.compile("(^(?P<space>\s+)entry\s%s\s(.*?)^(?P=space)exit$)" % entry,
                                                re.DOTALL | re.MULTILINE)
                inside_entry_ps = re_inside_entry_ps.search((policy_statent.group(3)))
                if inside_entry_ps is not None:
                    re_prepend = re.compile("(^(\s+as-path-prepend\s(\d+)\s1\s))", re.DOTALL | re.MULTILINE)
                    prepend = re_prepend.search(inside_entry_ps.group(3))
                    if prepend is not None:
                        responce_entry[entry] = (prepend.group(2))
        result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 108035, result)
        if '2' not in current_bras or (current_bras['2'][8] == '0'):
            empty_entry = ''
            for entry in required_entry:
                if responce_entry.get(entry, None) is None:
                    empty_entry += ', ' + str(entry)
            if empty_entry != '':
                result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 108035,
                                             'no vpls2 or no vpls2-priority and no as-path prepend %s' % (
                                                 str(empty_entry)), result)
        elif current_bras['2'][8] == '8192':
            empty_entry = ''
            for entry in required_entry:
                if responce_entry.get(entry, None) is None:
                    empty_entry += ', ' + str(entry)
            if empty_entry != '':
                # "all right, prepends not have to, vpls 2 priority = %s" % (current_bras['2'][8])
                pass
            else:
                # "we have error, "
                result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 108035,
                                             'vpls2 have priority %s and have as-path prepend %s' % (
                                                 str(current_bras['2'][8]), empty_entry), result)
        else:
            # "will be error2, vpls 2 priority = %s " %(current_bras['2'][8])
            result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 108035,
                                         'vpls 2 priority = %s ' % (str(current_bras['2'][8])), result)

        for num, info in current_bras.items():
            if num in ['1', '2', '4'] or num in cur_nocheck:
                continue

            result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 108012, result)
            if info[1] is False:
                result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 108012,
                                             '[%s][vpls %s] mesh-sdp has difference number. Must be: %s' %
                                             (str(main_bras_name), num, num), result)
            result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 108013, result)
            if info[1] is None and info[6] == 'None':
                # print("-----------------info----------------------")
                # print(info)
                # print("[%s][vpls %s] mesh-sdp not found." % (str(mgmt), num))
                result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 108013,
                                             '[%s][vpls %s] mesh-sdp not found.' % (str(main_bras_name), num), result)

        # double_bras_name = mgmt.get_attr('double_bras')
        # if not double_bras_name:
        #     return result
        # try:
        # mgmt2 = ManagedObject.objects.get(name=double_bras_name)
        # config2 = mgmt2.config.get_gridvcs().get(mgmt2.id)

        # except:
        #    return result
        if double_bras_name == '':
            return result

        # double_bras = get_vpls_dict(config2)
        d_vplss_double = dlocal_d_config[double_bras_name]['echo "Service Configuration"']['service']['vplss']
        double_bras = get_vpls_dict(d_vplss_double)
        doub_nocheck = []

        for vpls in double_bras:
            if 'NOCHECK' in double_bras[vpls][3].upper():
                doub_nocheck.append(vpls)
            result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 108003, result)
            if int(double_bras[vpls][4]) > 9100:
                result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 108003,
                                             "[%s][vpls %s] MTU = %s, should be le 9100" % (
                                                 str(double_bras_name), str(vpls), str(double_bras[vpls][4])),
                                             result)

        for vpls in double_bras:
            if vpls not in current_bras:
                continue
            result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 108004, result)
            if int(double_bras[vpls][4]) != int(current_bras[vpls][4]):
                result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 108004,
                                             "[%s][vpls %s] MTU = %s, [%s][vpls %s] MTU = %s" %
                                             (str(main_bras_name), str(vpls), str(current_bras[vpls][4]),
                                              str(double_bras_name), str(vpls), str(double_bras[vpls][4])),
                                             result)

        diff_cd = list(set(current_bras.keys()).difference(double_bras.keys()))
        diff_dc = list(set(double_bras.keys()).difference(current_bras.keys()))

        diff_cd = list(set(diff_cd).difference(cur_nocheck))
        diff_dc = list(set(diff_dc).difference(doub_nocheck))

        result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 108014, result)
        if diff_cd != []:
            result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 108014,
                                         '[%s] Excessive vpls: %s' % (str(main_bras_name), ', '.join(diff_cd)), result)

        result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 108014, result)
        if diff_dc != []:
            result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 108014,
                                         '[%s] Excessive vpls: %s' % (str(double_bras_name), ', '.join(diff_cd)),
                                         result)

        for vpls in [x for x in current_bras.keys() if x in double_bras.keys()]:
            if vpls in ['1', '2'] or vpls in cur_nocheck or vpls in doub_nocheck:
                continue

            diff_cd = list(set(current_bras[vpls][0]).difference(double_bras[vpls][0]))
            diff_dc = list(set(double_bras[vpls][0]).difference(current_bras[vpls][0]))
            result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 108015, result)
            if diff_cd != []:
                result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 108015, '[%s][vpls %s] Excessive sap(s): %s' %
                                             (str(main_bras_name), vpls, ', '.join(diff_cd)), result)
            result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 108015, result)
            if diff_dc != []:
                result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 108015, '[%s][vpls %s] Excessive sap(s): %s' %
                                             (str(double_bras_name), vpls, ', '.join(diff_cd)), result)

            cur_is_shtdwn = current_bras[vpls][2]
            doub_is_shtdwn = double_bras[vpls][2]
            result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 108016, result)
            if cur_is_shtdwn != doub_is_shtdwn:
                result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 108016,
                                             'Difference: [%s][vpls %s] is %s. [%s][vpls %s] is %s.' %
                                             (str(main_bras_name), vpls, 'no shutdown' if cur_is_shtdwn else 'shutdown',
                                              str(double_bras_name), vpls,
                                              'no shutdown' if doub_is_shtdwn else 'shutdown'), result)

        # cur_srrp = get_srrp(config)
        # double_srrp = get_srrp(config2)
        d_current_vprns = dlocal_d_config[main_bras_name]['echo "Service Configuration"']['service']['vprns']
        cur_srrp = get_srrp(d_current_vprns)
        d_double_vprns = dlocal_d_config[double_bras_name]['echo "Service Configuration"']['service']['vprns']
        double_srrp = get_srrp(d_double_vprns)

        print(cur_srrp)
        for srrp in cur_srrp:
            # print(srrp)
            if srrp not in double_srrp:
                continue
            result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 108017, result)
            if cur_srrp[srrp] == double_srrp[srrp]:
                result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 108017,
                                             "[srrp %s] priority = %s on both BSR" %
                                             (str(srrp), str(cur_srrp[srrp])),
                                             result)

        result = liboba.add_descr_to_result(result, "<<<<< check config differences between %s and %s >>>>>"
                                            % (str(main_bras_name), str(double_bras_name)) + "(%d/%d)")
        return result

    def rateindavpls_check(d_vplss):
        result = {}

        # re_vpls = re.compile("^(        vpls .+?)\n        exit$", re.MULTILINE | re.DOTALL)
        # re_sapconf = re.compile("^            (sap .+?)\n            exit$", re.MULTILINE | re.DOTALL)
        # re_sapnum = re.compile("^(sap .+?) create")
        # re_numvpls = re.compile("^        (vpls \w+)?")
        # re_ingress = re.compile("^                (ingress\n.+)                exit$", re.MULTILINE | re.DOTALL)
        # re_egress = re.compile("^                (egress\n.+)                exit$", re.MULTILINE | re.DOTALL)
        # vplses = re_vpls.findall(config)

        re_s_ingress = re.compile('^(?P<space>\s+)(ingress\n.*?)(?P=space)exit$', re.MULTILINE | re.DOTALL)
        re_s_egress = re.compile('^(?P<space>\s+)(egress\n.*?)(?P=space)exit$', re.MULTILINE | re.DOTALL)
        for num_vpls, vpls_content in d_vplss.items():
            if num_vpls == '1' or num_vpls == '2':
                continue
            declare_content = vpls_content.get('declare_content', {})
            saps = declare_content.get('saps', {})
            if saps == {}:
                print("ERROR, on VPLS %s no declare_content" % num_vpls)
                continue
            for sap_name, sap_content in saps.items():
                try:
                    sap_ingress = re_s_ingress.search(sap_content['content'])
                    sap_egress = re_s_egress.search(sap_content['content'])
                    result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 108002, result)
                    if sap_ingress is not None and sap_egress is not None:
                        ingress = sap_ingress.group(0)
                        egress = sap_egress.group(0)
                        if ((('rate' in ingress) and ('rate' in egress)) or (
                                ('qos 55' in ingress) and ('qos 55' in egress)) or (
                                ('SP-B2B-3' in ingress) and ('SP-B2B-3' in egress))):
                            continue
                        else:
                            result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 108002,
                                                         "%s %s dont have rate!!!" % (num_vpls, sap_name), result)
                    else:
                        result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 108002,
                                                     "%s %s dont have rate!!!" % (num_vpls, sap_name), result)
                except IndexError:
                    result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 108002,
                                                 "%s %s dont have rate!!!" % (num_vpls, sap_name), result)
                    continue
        #
        # for vpls in vplses:
        #     numvpls = re_numvpls.findall(vpls)  # nomer vpls
        #     if numvpls[0] == 'vpls 1' or numvpls[0] == 'vpls 2':  # skip vpls 1,2
        #         continue
        #     sapconf = re_sapconf.findall(vpls)
        #     for sap in sapconf:
        #         sapnum = re_sapnum.findall(sap)
        #         sapingress = re_ingress.findall(sap)
        #         sapegress = re_egress.findall(sap)
        #         result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 108002, result)
        #         try:
        #             if (('rate' in sapingress[0]) and ('rate' in sapegress[0]) or (
        #                     'qos 55' in sapingress[0] and 'qos 55' in sapegress[0]) or (
        #                     'SP-B2B-3' in sapingress[0] and 'SP-B2B-3' in sapegress[0])):
        #                 continue
        #             else:
        #                 result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 108002,
        #                                              "%s %s dont have rate!!!" % (numvpls[0], sapnum[0]), result)
        #                 # (numvpls[0],' with - ',sap,'VSE NE OK!!!!!!!')
        #         except IndexError:
        #             result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 108002,
        #                                          "%s %s dont have rate!!!" % (numvpls[0], sapnum[0]), result)
        result = liboba.add_descr_to_result(result, "<<<<< check rate in VPLS >>>>> (%d/%d)")
        return result

    def check_vpls_saps_inner_tags(config):
        re_sap = "lag-(\d+:\d+)\.(\d+)"
        result = {}
        error_damage = 0

        def get_vpls_dict(cnfg):
            re_vpls = re.compile("^(        vpls .+?)\n        exit$", re.MULTILINE | re.DOTALL)
            re_numvpls = re.compile("^        vpls (\w+)?")
            # re_vpls_cust = re.compile("(customer .+?) create")
            re_vpls_desc = re.compile("description \"(.+?)\"")
            re_shut_vpls = re.compile("^            (shutdown)$", re.MULTILINE | re.DOTALL)
            re_mesh = re.compile("^            mesh-sdp \d*?:(\d*?)\s", re.MULTILINE | re.DOTALL)
            re_sapconf = re.compile("^            (sap .+?)\n            exit$", re.MULTILINE | re.DOTALL)
            # re_sapnum = re.compile("^(sap .+?) create")
            re_sapnum = re.compile("^(sap .+?)\s")
            vplses = re_vpls.findall(cnfg)
            vpls_conf = {}
            for vpls in vplses:
                numvpls = re_numvpls.findall(vpls)[0]  # nomer vpls
                descvpls = re_vpls_desc.findall(vpls)
                # custvpls= re_vpls_cust.findall(vpls)
                sapconf = re_sapconf.findall(vpls)
                saps = []
                vpls_conf[numvpls] = []
                for sap in sapconf:
                    sapnum = re_sapnum.findall(sap)[0]
                    saps.append(sapnum)
                vpls_conf[numvpls].append(saps)
                mesh = re_mesh.findall(vpls)
                if mesh == []:
                    vpls_conf[numvpls].append(None)
                else:
                    vpls_conf[numvpls].append(mesh[0] == numvpls)
                if not re_shut_vpls.search(vpls):
                    vpls_conf[numvpls].append(True)
                else:
                    vpls_conf[numvpls].append(False)
                if descvpls == []:
                    vpls_conf[numvpls].append('')
                else:
                    vpls_conf[numvpls].append(descvpls[0])

            return vpls_conf

        vpls_dict = get_vpls_dict(config)

        for key in vpls_dict.keys():
            saps = vpls_dict[key][0]
            for sap1 in saps:
                match1 = re.search(re_sap, sap1)
                for sap2 in saps:
                    if sap2 == sap1:
                        continue
                    match2 = re.search(re_sap, sap2)
                    if match1 and match2:
                        if match1.group(1) == match2.group(1) and match1.group(2) != match2.group(2):

                            # ___________________________#DDS-13401_start#_______________________________________________________________
                            sap_potential_err = {sap1: '', sap2: ''}
                            re_horizon_group1 = str(sap1) + ' split-horizon-group '
                            re_hg1 = re.compile('%s(\S+)' % re_horizon_group1)
                            horizon_group1 = re_hg1.finditer(config)
                            for h_group1 in horizon_group1:
                                sap1_group = h_group1.group(1)
                                sap_potential_err[sap1] = sap1_group

                            re_horizon_group2 = str(sap2) + ' split-horizon-group '
                            re_hg2 = re.compile('%s(\S+)' % re_horizon_group2)
                            horizon_group2 = re_hg2.finditer(config)
                            for h_group2 in horizon_group2:
                                sap2_group = h_group2.group(1)
                                sap_potential_err[sap2] = sap2_group

                            result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 108034, result)
                            if sap_potential_err == {}:
                                # "our error,empty dict"
                                result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 108034,
                                                             'vpls %s has SAPs with common outer-tag and different inner-tags: %s and %s' % (
                                                                 key, sap1, sap2), result)
                            elif sap_potential_err[sap1] != sap_potential_err[sap2]:
                                # "our error diffrent group"
                                result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 108034,
                                                             'vpls %s has SAPs with common outer-tag and different inner-tags: %s and %s' % (
                                                                 key, sap1, sap2), result)
                            else:
                                # "group equivalent will be continue"
                                continue
        # ___________________________#DDS-13401_end#_______________________________________________________________
        # result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 108002,
        #                             'vpls %s has SAPs with common outer-tag and different inner-tags: %s and %s' % (
        #                                 key, sap1, sap2), result)

        result = liboba.add_descr_to_result(result,
                                            "<<<<< check vpls SAPs inner-tags kb: https://kb.ertelecom.ru/pages/viewpage.action?pageId=2785397 >>>>> (%d/%d)")

        return result

    def check_iptv(config):
        result = {}

        re_vprn_600 = re.compile('(?P<config>^(?P<space>\s+)vprn\s+600.*?^(?P=space)exit$)', re.DOTALL | re.MULTILINE)
        re_vprn_600_no_sh = re.compile('(?P<config>^(?P<space>\s+)vprn\s+600.*?    no\s+shutdown.*?^(?P=space)exit$)',
                                       re.DOTALL | re.MULTILINE)
        re_int = re.compile('(?P<config>^(?P<space>\s+)interface\s+\"(?P<name>\S+)\"\s+create.*?^(?P=space)exit$)',
                            re.DOTALL | re.MULTILINE)
        re_int_name = re.compile('(BACKBONE-1|BACKBONE-2|MCAST-SOURCE-1|MCAST-SOURCE-2|Loopback600|MCAST-DOWNLINK-)')
        re_int_qos_in = re.compile('ingress\s*qos\s+600\s*exit')
        re_int_qos_eg = re.compile('egress\s*qos\s+600\s*exit')
        re_int_address = re.compile('address (?P<ip>\S*?)\/\d+')

        re_pim = re.compile('(?P<config>^(?P<space>\s+)pim.*?^(?P=space)exit$)', re.DOTALL | re.MULTILINE)
        re_pim_no_sh = re.compile('(?P<config>^(?P<space>\s+)pim.*?    no\s+shutdown.*?^(?P=space)exit$)',
                                  re.DOTALL | re.MULTILINE)
        re_pim_int = re.compile('(?P<config>^(?P<space>\s+)interface\s+\"(?P<name>\S+)\".*?^(?P=space)exit$)',
                                re.DOTALL | re.MULTILINE)

        re_ospf = re.compile('(?P<config>^(?P<space>\s+)ospf.*?^(?P=space)exit$)', re.DOTALL | re.MULTILINE)
        re_ospf_no_sh = re.compile('(?P<config>^(?P<space>\s+)ospf.*?    no\s+shutdown.*?^(?P=space)exit$)',
                                   re.DOTALL | re.MULTILINE)
        re_ospf_int = re_pim_int
        re_area_0000 = re.compile('(?P<config>^(?P<space>\s+)area\s+0\.0\.0\.0.*?^(?P=space)exit$)',
                                  re.DOTALL | re.MULTILINE)
        re_area_0251 = re.compile('area\s+0\.0\.0\.251\s*nssa\s*no\s+summaries\s*exit\s*interface\s+"MCAST-SOURCE-1"\s*'
                                  'mtu\s+1500\s*metric\s+2\s*bfd-enable\s*no\s+shutdown\s*exit\s*exit',
                                  re.DOTALL | re.MULTILINE)
        re_area_0252 = re.compile('area\s+0\.0\.0\.252\s*nssa\s*no\s+summaries\s*exit\s*interface\s+"MCAST-SOURCE-2"\s*'
                                  'mtu\s+1500\s*metric\s+10\s*bfd-enable\s*no\s+shutdown\s*exit\s*exit',
                                  re.DOTALL | re.MULTILINE)

        ints_check_sh_only = ['Loopback600']
        ints_check_all = ['BACKBONE-1', 'BACKBONE-2', 'MCAST-SOURCE-1', 'MCAST-SOURCE-2']
        vprn_found = 0
        all_interfaces = []
        loopback_address = ''

        for vprn in re_vprn_600.finditer(config):
            vprn_conf = vprn.group('config')
            if not re_vprn_600_no_sh.search(vprn_conf):
                continue
            vprn_found = 1

            for interface in re_int.finditer(vprn_conf):
                int_name = interface.group('name')
                int_conf = interface.group('config')
                if re_int_name.search(int_name) is None:
                    continue
                all_interfaces.append(int_name)
                if int_name == 'Loopback600':
                    ip_match = re_int_address.search(int_conf)
                    if ip_match is not None:
                        loopback_address = ip_match.group('ip')

                result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 130001, result)
                if int_conf.find('shutdown') != -1:
                    result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 130001, "Interface %s shutdown" % int_name,
                                                 result)

                if int_name in ints_check_sh_only:
                    continue

                result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 130002, result)
                if int_conf.find('ip-mtu 1500') == -1:
                    result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 130002, "Interface %s, check ip-mtu"
                                                 % int_name, result)

                result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 130003, result)
                if re_int_qos_in.search(int_conf) is None:
                    result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 130003, "Interface %s, check qos ingress"
                                                 % int_name, result)

                result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 130003, result)
                if re_int_qos_eg.search(int_conf) is None:
                    result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 130003, "Interface %s, check qos egress"
                                                 % int_name, result)

                if int_name not in ints_check_all:
                    continue

                result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 130004, result)
                if int_conf.find('bfd 100 receive 100 multiplier 3') == -1:
                    result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 130004, "Interface %s, check bfd"
                                                 % int_name, result)

            pim = re_pim.search(vprn_conf)
            pim_ints = []
            result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 130005, result)
            if pim is None:
                result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 130005, "pim not found", result)
            else:
                pim_conf = pim.group('config')
                if re_pim_no_sh.search(pim_conf) is None:
                    result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 130005, "pim shutdown", result)
                else:
                    pim_ints = []
                    for interface in re_pim_int.finditer(pim_conf):
                        int_name = interface.group('name')
                        int_conf = interface.group('config')
                        pim_ints.append(int_name)
                        result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 130006, result)
                        if int_name in ints_check_all and int_conf.find('bfd-enable') == -1:
                            result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 130006, "Pim, interface %s, check bfd"
                                                         % int_name, result)
                    for int_name in set(all_interfaces):
                        result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 130001, result)
                    for int_name in set(pim_ints):
                        result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 130001, result)
                    for int_name in (set(all_interfaces) - set(pim_ints)):
                        result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 130001, "Pim, miss interface %s"
                                                     % int_name, result)
                    for int_name in (set(pim_ints) - set(all_interfaces)):
                        result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 130001, "Pim, excess interface %s"
                                                     % int_name, result)

                    result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 130007, result)
                    if pim_conf.find('rpf-table both') == -1:
                        result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 130007, "Pim, check rpf-table"
                                                     , result)
                    result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 130008, result)
                    if pim_conf.find('non-dr-attract-traffic') == -1:
                        result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 130008, "Pim, check non-dr-attract-traffic"
                                                     , result)

                    result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 130009, result)
                    if pim_conf.find('address ' + loopback_address) == -1:
                        result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 130009, "Pim, check static address - not %s"
                                                     % loopback_address, result)
                    result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 130009, result)
                    if pim_conf.find('anycast ' + loopback_address) == -1:
                        result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 130009, "Pim, check anycast address - not %s"
                                                     % loopback_address, result)

                    result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 130010, result)
                    if pim_conf.find('group-prefix 225.0.55.0/24') == -1:
                        result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 130010, "Pim, check group-prefix 225.0.55.0/24"
                                                     # % loopback_address
                                                     , result)
                    result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 130010, result)
                    if pim_conf.find('group-prefix 225.0.56.0/22') == -1:
                        result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 130010, "Pim, check group-prefix 225.0.56.0/22"
                                                     # % loopback_address
                                                     , result)
            if 'MCAST-SOURCE-1' in pim_ints:
                pim_ints.remove('MCAST-SOURCE-1')
            if 'MCAST-SOURCE-2' in pim_ints:
                pim_ints.remove('MCAST-SOURCE-2')
            pim_ints.append('Loopback0')
            bfd_check = ['BACKBONE-1', 'BACKBONE-2']
            ospf = re_ospf.search(vprn_conf)
            result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 130011, result)
            if ospf is None:
                result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 130011, "ospf not found", result)
            else:
                ospf_conf = ospf.group('config')
                if re_ospf_no_sh.search(ospf_conf) is None:
                    result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 130011, "ospf shutdown", result)
                else:
                    ospf_ints = []

                    result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 130012, result)
                    if re_area_0251.search(ospf_conf) is None:
                        result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 130012, "Ospf, check area 0.0.0.251"
                                                     , result)
                    result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 130012, result)
                    if re_area_0252.search(ospf_conf) is None:
                        result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 130012, "Ospf, check area 0.0.0.252"
                                                     , result)
                    area0 = re_area_0000.search(ospf_conf)

                    result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 130013, result)
                    if area0 is None:
                        result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 130013, "ospf, area0 not found", result)
                    else:
                        area0_conf = area0.group('config')
                        for interface in re_ospf_int.finditer(area0_conf):
                            int_name = interface.group('name')
                            int_conf = interface.group('config')
                            ospf_ints.append(int_name)
                            result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 130006, result)
                            if int_name in bfd_check and int_conf.find('bfd-enable') == -1:
                                result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 130006, "Ospf, interface %s, check bfd"
                                                             % int_name, result)

                for int_name in set(pim_ints):
                    result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 130001, result)
                for int_name in set(ospf_ints):
                    result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 130001, result)
                for int_name in (set(pim_ints) - set(ospf_ints)):
                    result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 130001, "Ospf, area0 miss interface %s"
                                                 % int_name, result)
                for int_name in (set(ospf_ints) - set(pim_ints)):
                    result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 130001, "Ospf, area0 excess interface %s"
                                                 % int_name, result)

        result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 130000, result)
        if not vprn_found:
            result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 130000, "No vprn 600", result)

        result = check_qos_sap_ineg(config, result, True)

        result = liboba.add_descr_to_result(result, "<<<<< check IPTV, ask your MRAO >>>>> (%d/%d)")
        return result

    def check_raddb(config):
        result = {}
        f = open('/opt/noc/lib/boba/data/raddb_migrated_cities', 'r')
        data = f.read()
        cities = data.split('\n')
        for city in cities:
            if city == '':
                continue
            if city in mgmt.name:
                break
        else:
            return result

        re_rsp = re.compile(
            '(?P<config>^(?P<space>\s+)radius-server-policy\s+\"RAD-PPPOE-ERTELECOM\"\s+create(?!\s*exit).*?^(?P=space)exit$)'
            , re.DOTALL | re.MULTILINE)
        re_rsp_srv = re.compile('server\s+\d+\s+name\s+\"(?P<name>\S+)\"')
        re_vprn_rad_srv = re.compile(
            '(?P<config>^(?P<space>\s+)vprn\s+100.*?(?P<config_inner>^(?P<space2>\s+)radius-server.*?^(?P=space2)exit$).*?^(?P=space)exit$)'
            , re.DOTALL | re.MULTILINE)
        re_rad_srv_coa = re.compile(
            'server\s+\"(?P<name>\S+)\"\s+address\s+(?P<address>\S+).*\s*(?P<accept_coa>accept-coa)?')
        re_prefix_list = re.compile(
            '(?P<config>^(?P<space>\s+)ip-prefix-list\s+\"PL-RADIUS-SRV\"\s+create(?!\s*exit).*?^(?P=space)exit$)'
            , re.DOTALL | re.MULTILINE)

        rsp_srv_ideal = {'RADDB-1', 'RADDB-2'}
        rsp_match = re_rsp.search(config)
        result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 146000, result)
        if rsp_match is None:
            result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 146000, "RAD-PPPOE-ERTELECOM not found", result)
            result = liboba.add_descr_to_result(result, "<<<<< check RADDB >>>>> (%d/%d)")
            return result
        rsp_conf = rsp_match.group('config')
        rsp_srv_real = set()
        for rsp_srv_match in re_rsp_srv.finditer(rsp_conf):
            rsp_srv_real.add(rsp_srv_match.group('name'))
        for diff in rsp_srv_ideal:
            result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 146001, result)
        for diff in (rsp_srv_ideal - rsp_srv_real):
            result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 146001, "Server %s not found in RAD-PPPOE-ERTELECOM" % diff,
                                         result)

        vprn_rad_srv_match = re_vprn_rad_srv.search(config)
        result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 146002, result)
        if vprn_rad_srv_match is None:
            result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 146002, "vprn 100 radius-server not found", result)
            result = liboba.add_descr_to_result(result, "<<<<< check RADDB >>>>> (%d/%d)")
            return result

        rad_srv_conf = vprn_rad_srv_match.group('config_inner')
        rad_srvs = {}
        for rad_srv_match in re_rad_srv_coa.finditer(rad_srv_conf):
            name = rad_srv_match.group('name')
            address = rad_srv_match.group('address')
            accept_coa = rad_srv_match.group('accept_coa')
            rad_srvs[name] = {'address': address,
                              'accept_coa': accept_coa}

        raddb_addresses = []
        for diff in rsp_srv_ideal:
            result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 146003, result)
        for diff in (rsp_srv_ideal - set(rad_srvs.keys())):
            result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 146003,
                                         "Server %s not found in vprn 100 radius-server" % diff, result)
        for same in (rsp_srv_ideal & set(rad_srvs.keys())):
            raddb_addresses.append(rad_srvs[same]['address'])
            result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 146004, result)
            if rad_srvs[same]['accept_coa'] is None:
                result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 146004,
                                             "Server %s doesn't have accept-coa in vprn 100" % diff, result)

        result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 146005, result)
        prefix_list_match = re_prefix_list.search(config)
        if prefix_list_match is None:
            result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 146005, "ip-prefix-list PL-RADIUS-SRV not found", result)
            result = liboba.add_descr_to_result(result, "<<<<< check RADDB >>>>> (%d/%d)")
            return result
        prefix_list_conf = prefix_list_match.group('config')
        for address in raddb_addresses:
            result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 146006, result)
            if 'prefix %s/32' % address not in prefix_list_conf:
                result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 146006,
                                             "prefix %s/32 not found in PL-RADIUS-SRV" % address, result)

        result = liboba.add_descr_to_result(result, "<<<<< check RADDB >>>>> (%d/%d)")
        return result

    def check_sub_default(dhcp_servers, sub_defaults_config, static_routes, ifaces):
        result = {}
        loopback105_addr = ifaces.get('interface "Loopback105"', {}).get('addr', 'None/') or 'None/'
        loopback105_addrv6 = ifaces.get('interface "Loopback105"', {}).get('addrv6', 'None/') or 'None/'

        # re_sub_iface = re.compile(
        #    '(?P<config>^(?P<space>\s+)subscriber-interface\s+\"SUB-DEFAULT\"\s+create.*?^(?P=space)exit$)',
        #    re.DOTALL | re.MULTILINE)
        re_address = re.compile(
            '(?:address|prefix)\s+(?P<address>(?:(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\/\d+)|(?:\S*\/\d+))')
        re_giface = re.compile(
            '^(?P<space>\s*)group-interface\s+\"(?P<name>\S+)\"\s+create(?!\s*exit)\s*(?P<config>.*?)^(?P=space)exit',
            re.DOTALL | re.MULTILINE)
        re_dhcp6 = re.compile('^(?P<space>\s*)dhcp6\s*(?P<config>.*?)^(?P=space)exit', re.DOTALL | re.MULTILINE)
        re_dhcp = re.compile('^(?P<space>\s*)dhcp(?!6)\s*(?P<config>.*?)^(?P=space)exit', re.DOTALL | re.MULTILINE)
        re_srrp = re.compile('^(?P<space>\s*)srrp\s+(?P<name>\S+)\s+create(?!\s*exit)\s*(?P<config>.*?)^(?P=space)exit',
                             re.DOTALL | re.MULTILINE)

        re_src_addr = re.compile('^\s*source-address\s+(\S+)\s*$', re.MULTILINE)
        re_lnk_addr = re.compile('^\s*link-address\s+(\S+)\s*$', re.MULTILINE)
        re_srv_addr = re.compile('^\s*server\s+(\S+)\s*$', re.MULTILINE)
        re_proxy = re.compile('(?P<config>proxy-server.*?exit$)', re.DOTALL | re.MULTILINE)
        re_relay = re.compile('(?P<config>^(?P<space>\s+)relay.*?^(?P=space)exit$)', re.DOTALL | re.MULTILINE)
        re_emu_srv = re.compile('emulated-server (\S+)')
        re_gi_address = re.compile('gi-address (\S+)')

        # sub_iface_conf = ''
        # for sub_iface_match in re_sub_iface.finditer(config):
        #    sub_iface_conf += sub_iface_match.group('config')
        sub_iface_conf = sub_defaults_config
        result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 104012, result)
        if sub_iface_conf == '':
            result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 104012, 'Subscriber-interface "SUB-DEFAULT" not found',
                                         result)
            result = liboba.add_descr_to_result(result, "<<<<< check SUB-DEFAULT nets >>>>> (%d/%d)")
            return result

        real_nets = []
        real_nets = parse_sub_default_address(sub_iface_conf)  # ________DDS-13452
        # for address_match in re_address.finditer(sub_iface_conf):
        #     address = address_match.group('address')
        #     if ip.is_ipv4_prefix(address):
        #         address = ip.IPv4(address)
        #     else:
        #         address = ip.IPv6(address)
        #     net_address = address.first
        #     real_nets.append(str(net_address))

        dhcp_server_to_check = ['DEFAULT-DHCP-ANYCAST', 'DEFAULT-DHCP-V6-ANYCAST']
        ideal_nets = []
        for dhcp_server in dhcp_server_to_check:
            result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 104011, result)
            if dhcp_server not in dhcp_servers:
                result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 104011, '%s not found' % dhcp_server, result)
            try:
                for pool in dhcp_servers[dhcp_server]:
                    ideal_nets.extend(dhcp_servers[dhcp_server][pool])
            except Exception as ex:
                print(ex)

        for diff in set(ideal_nets):
            result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 104013, result)
        for diff in (set(ideal_nets) - set(real_nets)):
            result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 104013, 'Miss %s in SUB-DEFAULT' % diff, result)

        for giface_match in re_giface.finditer(sub_iface_conf):
            giface_conf = giface_match.group('config')
            giface_name = giface_match.group('name')
            dhcp6_match = re_dhcp6.search(giface_conf)
            result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 104030, result)
            if dhcp6_match is None:
                result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 104030, 'DHCP6 not found on %s in SUB-DEFAULT'
                                             % giface_name, result)
            else:
                dhcp6_conf = dhcp6_match.group('config')
                src_addr = re_src_addr.search(dhcp6_conf)
                lnk_addr = re_lnk_addr.search(dhcp6_conf)
                srv_addr = re_srv_addr.search(dhcp6_conf)

                if src_addr is None:
                    src_addr = 'None'
                else:
                    src_addr = src_addr.group(1)

                if lnk_addr is None:
                    lnk_addr = 'None'
                else:
                    lnk_addr = lnk_addr.group(1)

                if srv_addr is None:
                    srv_addr = 'None'
                else:
                    srv_addr = srv_addr.group(1)

                result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 104031, result)
                if ((src_addr not in loopback105_addrv6) and (loopback105_addrv6 not in src_addr)):
                    # if src_addr != loopback105_addrv6:
                    # print('src_addr', src_addr, 'loopback105_addrv6', loopback105_addrv6)
                    result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 104031, 'GIface %s in SUB-DEFAULT, source-address '
                                                                            '= %s, Loopback105 ipv6 = %s.'
                                                 % (giface_name, src_addr, loopback105_addrv6), result)
                result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 104032, result)
                if ((lnk_addr not in loopback105_addrv6) and (loopback105_addrv6 not in lnk_addr)):
                    # if lnk_addr != loopback105_addrv6:
                    # print('lnk_addr', lnk_addr, 'loopback105_addrv6', loopback105_addrv6)
                    result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 104032, 'GIface %s in SUB-DEFAULT, link-address '
                                                                            '= %s, Loopback105 ipv6 = %s.'
                                                 % (giface_name, lnk_addr, loopback105_addrv6), result)
                result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 104033, result)
                # print("behind if")
                # print("!!!!!!!!!!!",'srv_addr', srv_addr, 'loopback105_addrv6', loopback105_addrv6)
                if ((srv_addr not in loopback105_addrv6) and (loopback105_addrv6 not in srv_addr)):
                    #  srv_addr != loopback105_addrv6:
                    # print('srv_addr', srv_addr, 'loopback105_addrv6', loopback105_addrv6)
                    result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 104033, 'GIface %s in SUB-DEFAULT, server = %s, '
                                                                            'Loopback105 ipv6 = %s.'
                                                 % (giface_name, srv_addr, loopback105_addrv6), result)

                proxy = re_proxy.search(dhcp6_conf)
                result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 104034, result)
                if proxy is None:
                    result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 104034, 'GIface %s in SUB-DEFAULT, '
                                                                            'proxy-server not found.'
                                                 % (giface_name), result)
                elif 'no shutdown' not in proxy.group('config'):
                    result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 104035, 'GIface %s in SUB-DEFAULT, '
                                                                            'proxy-server shutdown.'
                                                 % (giface_name), result)

                relay = re_relay.search(dhcp6_conf)
                result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 104036, result)
                if relay is None:
                    result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 104036, 'GIface %s in SUB-DEFAULT, '
                                                                            'relay not found.'
                                                 % (giface_name), result)
                elif 'no shutdown' not in relay.group('config'):
                    result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 104037, 'GIface %s in SUB-DEFAULT, '
                                                                            'relay shutdown.'
                                                 % (giface_name), result)

            dhcp_match = re_dhcp.search(giface_conf)
            result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 104030, result)
            if dhcp_match is None:
                result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 104030, 'DHCP not found on %s in SUB-DEFAULT'
                                             % giface_name, result)
            else:
                dhcp_conf = dhcp_match.group('config')
                result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 104039, result)
                if re.search('^                        no shutdown$', dhcp_conf, re.MULTILINE) is None:
                    result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 104039, 'DHCP shutdown on %s in SUB-DEFAULT'
                                                 % giface_name, result)
                srv_addr = re_srv_addr.search(dhcp_conf)
                if srv_addr is None:
                    srv_addr = 'None'
                else:
                    srv_addr = srv_addr.group(1)
                result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 104033, result)
                if (srv_addr not in loopback105_addr) and (loopback105_addr not in srv_addr):
                    result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 104033, 'GIface %s in SUB-DEFAULT, server = %s, '
                                                                            'Loopback105 ip = %s.'
                                                 % (giface_name, srv_addr, loopback105_addr), result)

                proxy = re_proxy.search(dhcp_conf)
                # proxy = re_proxy.search(dhcp6_conf)  FIXING MSA-5940
                result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 104034, result)
                if proxy is None:
                    result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 104034, 'GIface %s in SUB-DEFAULT, '
                                                                            'proxy-server not found.'
                                                 % (giface_name), result)
                else:
                    proxy_conf = proxy.group('config')
                    result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 104035, result)
                    if 'no shutdown' not in proxy_conf:
                        result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 104035, 'GIface %s in SUB-DEFAULT, '
                                                                                'proxy-server shutdown.'
                                                     % (giface_name), result)
                    result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 104038, result)
                    if 'lease-time min 30' not in proxy_conf:
                        result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 104038, 'GIface %s in SUB-DEFAULT, '
                                                                                'proxy-server lease not min 30.'
                                                     % (giface_name), result)
                emu_srv = re_emu_srv.search(dhcp_conf)
                if emu_srv is not None:
                    emu_srv = emu_srv.group(1)

                gi_address = re_gi_address.search(dhcp_conf)
                if gi_address is not None:
                    gi_address = gi_address.group(1)

                result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 104040, result)
                if emu_srv is None or gi_address is None or emu_srv != gi_address:
                    result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 104040, 'GIface %s in SUB-DEFAULT,'
                                                                            'emulated-server = %s, '
                                                                            'gi-address = %s.'
                                                 % (giface_name, emu_srv, gi_address), result)

            result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 104041, result)
            if 'shcv-policy "DHCP-SHCV"' not in giface_conf:
                result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 104041, 'GIface %s in SUB-DEFAULT,'
                                                                        'shcv-policy "DHCP-SHCV" not found.'
                                             % (giface_name), result)
            srrp_match = re_srrp.search(giface_conf)
            result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 104042, result)
            if srrp_match is None:
                result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 104042, 'Srrp not found on %s in SUB-DEFAULT'
                                             % giface_name, result)
            else:
                srrp_conf = srrp_match.group('config')
                priority = re.search('priority (\d+)', srrp_conf)
                result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 104043, result)
                if 'no shutdown' not in srrp_conf:
                    result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 104043, 'GIface %s in SUB-DEFAULT, '
                                                                            'srrp shutdown.'
                                                 % (giface_name), result)
                if priority is None:
                    priority = 'None'
                else:
                    priority = priority.group(1)
                result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 104044, result)
                if priority not in ['190', '200']:
                    result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 104044, 'Srrp on %s in SUB-DEFAULT = %s, '
                                                                            'should be 190 or 200'
                                                 % (giface_name, priority), result)

        # ________DDS-13452 start
        subdefolt_if_ipv4 = [];
        static_rs_ipv4 = []
        # static_routeentries = parse_static_routes(config)
        static_routeentries = static_routes
        for subdefolt_iface in real_nets:
            if ip.is_ipv4_prefix(subdefolt_iface):
                subdefolt_iface = ip.IPv4(subdefolt_iface)
                subdefolt_if_ipv4.append(subdefolt_iface)
                for static_routeentry in static_routeentries:
                    if ip.is_ipv4_prefix(static_routeentry):
                        static_routeentry = ip.IPv4(static_routeentry)
                        static_rs_ipv4.append(static_routeentry)
                        if subdefolt_iface.contains(static_routeentry):
                            result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 104014, result)
                            if str(static_routeentry) != str(subdefolt_iface):
                                result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 104014,
                                                             'prefix %s found on subscriber-interface "SUB-DEFAULT" and found more specific static-route-entry %s - WRONG SETTING. DELETE static-route-entry %s '
                                                             % (str(subdefolt_iface), str(static_routeentry),
                                                                str(static_routeentry)), result)
                            elif str(static_routeentry) == str(subdefolt_iface):
                                result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 104014,
                                                             'prefix %s found on subscriber-interface "SUB-DEFAULT" and found static-route-entry %s- WRONG SETTING. DELETE static-route-entry %s '
                                                             % (str(subdefolt_iface), str(static_routeentry),
                                                                str(static_routeentry)), result)
                            else:
                                # "all right for subdefolt_iface %s few specific static-route-entry %s" %(str(subdefolt_iface), str(static_routeentry))
                                pass
        # _____DDS-13452 end

        result = liboba.add_descr_to_result(result, "<<<<< check SUB-DEFAULT nets >>>>> (%d/%d)")
        return result

    def check_ipoe_pools(config):
        result = {}

        re_sub_iface = re.compile(
            '(?P<config>^(?P<space>\s+)subscriber-interface\s+\"IPoE\"\s+create.*?^(?P=space)exit$)',
            re.DOTALL | re.MULTILINE)
        re_address = re.compile(
            'address\s+(?P<address>(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\/\d+)')
        re_user_db = re.compile('(?P<config>^(?P<space>\s+)local-user-db\s+\"LUDB\-DT\"\s+create.*?^(?P=space)exit$)',
                                re.DOTALL | re.MULTILINE)
        re_user_host = re.compile('(?P<config>^(?P<space>\s+)host\s+\"(?P<name>\S+)\"\s+create.*?^(?P=space)exit$)',
                                  re.DOTALL | re.MULTILINE)
        re_prefix = re.compile(
            'ip-prefix\s+(?P<prefix>(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\/\d+)')
        re_auth_policy = re.compile('auth-policy\s+\"AUTH\-IPOE\"')
        re_prefix_list = re.compile('(?P<config>^(?P<space>\s+)prefix-list\s+\"PL\-STATIC\-IP\".*?^(?P=space)exit$)',
                                    re.DOTALL | re.MULTILINE)
        re_prefix_list_prefix = re.compile(
            'prefix\s+(?P<prefix>(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\/\d+)(?P<longer>\s+longer)?')

        sub_iface_conf = ''
        for sub_iface_match in re_sub_iface.finditer(config):
            sub_iface_conf += sub_iface_match.group('config')
        result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 147001, result)
        if sub_iface_conf == '':
            result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 147001, 'subscriber-interface "IPoE" NOT FOUND', result)
            result = liboba.add_descr_to_result(result, "<<<<< check IPoE pools >>>>> (%d/%d)")
            return result

        ideal_nets = []
        for address_match in re_address.finditer(sub_iface_conf):
            address = address_match.group('address')
            address = ip.IPv4(address)
            net_address = address.first
            ideal_nets.append(str(net_address))

        #  ideal_nets
        real_nets = []

        user_db_conf = ''
        for user_db_match in re_user_db.finditer(config):
            user_db_conf += user_db_match.group('config')
        for user_host_match in re_user_host.finditer(user_db_conf):
            user_host_conf = user_host_match.group('config')
            user_host_name = user_host_match.group('name')
            for prefix_match in re_prefix.finditer(user_host_conf):
                real_nets.append(prefix_match.group('prefix'))
            result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 147002, result)
            if re_auth_policy.search(user_host_conf) is None:
                result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 147002,
                                             'auth-policy "AUTH-IPOE" NOT FOUND in host "%s"' % user_host_name, result)

        # real_nets
        for diff in set(ideal_nets):
            result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 147003, result)
        for diff in (set(ideal_nets) - set(real_nets)):
            result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 147003, 'MISS %s IN local-user-db "LUDB-DT"' % diff, result)

        real_nets = []
        prefix_list_conf = ''
        for prefix_list_match in re_prefix_list.finditer(config):
            prefix_list_conf += prefix_list_match.group('config')
        for prefix_match in re_prefix_list_prefix.finditer(prefix_list_conf):
            prefix = prefix_match.group('prefix')
            longer = prefix_match.group('longer')
            real_nets.append(prefix)
            result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 147004, result)
            if longer is None and prefix in ideal_nets:
                result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 147004,
                                             'Prefix %s is not "longer" in PL-STATIC-IP' % prefix, result)

        for diff in set(ideal_nets):
            result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 147005, result)
        for diff in (set(ideal_nets) - set(real_nets)):
            for na in real_nets:
                if ip.IPv4(na).contains(ip.IPv4(diff)):
                    break
            else:
                result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 147005, 'MISS %s IN "PL-STATIC-IP"' % diff, result)

        result = liboba.add_descr_to_result(result, "<<<<< check IPoE nets >>>>> (%d/%d)")
        return result

    def get_all_bsrs_configs():
        current_bsr_name = mgmt.name
        name_parts = re.split('\d\d', current_bsr_name, 1)
        configs = {}
        all_bsrs = ManagedObject.objects.filter(name__startswith=name_parts[0], name__endswith=name_parts[1])
        for bsr in all_bsrs:
            configs[bsr.name] = bsr.config.get_gridvcs().get(bsr.id)
        return configs

    def get_vpls_dict_all_checks(cnfg):
        re_vpls = re.compile("^(        vpls .+?)\n        exit$", re.MULTILINE | re.DOTALL)
        re_numvpls = re.compile("^        vpls (\w+)?")
        re_vpls_desc = re.compile("description \"(.+?)\"")
        re_shut_vpls = re.compile("^            (shutdown)$", re.MULTILINE | re.DOTALL)
        re_mesh = re.compile("^            mesh-sdp \d*?:(\d*?)\s", re.MULTILINE | re.DOTALL)
        re_sapconf = re.compile("^            (sap .+?)\n            exit$", re.MULTILINE | re.DOTALL)
        re_sapnum = re.compile("^(sap .+?)\s")
        re_mtu = re.compile(r"^\s*service-mtu (?P<mtu>\d+)", re.MULTILINE)
        re_mesh_no_sh = re.compile("^            mesh-sdp \d*?:(\d*?)\screate\s*no shutdown", re.MULTILINE | re.DOTALL)
        re_bgp_vpls = re.compile("^            bgp-vpls.+?\sve-id (\d+).*?\n            exit$",
                                 re.MULTILINE | re.DOTALL)
        re_monitor_oper_group = re.compile(r"            bgp$.*?monitor-oper-group \"VRRP-3\".*?\n            exit$",
                                           re.MULTILINE | re.DOTALL)
        vplses = re_vpls.findall(cnfg)
        vpls_conf = {}
        for vpls in vplses:
            numvpls = re_numvpls.findall(vpls)[0]  # nomer vpls
            descvpls = re_vpls_desc.findall(vpls)
            sapconf = re_sapconf.findall(vpls)
            saps = []
            vpls_conf[numvpls] = {}
            saps_desc = {}  # ___________DDS-13570_______________________

            # 0 - saps
            for sap in sapconf:
                sapnum = re_sapnum.findall(sap)[0]
                saps.append(sapnum)
                # ______DDS-13570 - parse start_____________________________

                if numvpls not in ['1', '2', '3', '4', '5', '6', '7', '8', '9', '10']:
                    saps_desc[sapnum] = [sap]

                    re_short_lag = re.compile("^(sap\slag\S(\d+))", re.MULTILINE | re.DOTALL)
                    short_lag = (re_short_lag.search(sap)).group(2)
                    re_from_echo = re.compile(
                        "^(echo\s+\"LAG\s+Configuration\"\s+(.*?)(^(?P<space>\s+)lag\s+%s(.*?)\n(?P=space)exit))" % (
                            str(short_lag)), re.MULTILINE | re.DOTALL)
                    lag_from_echo = re_from_echo.search(cnfg)
                    if lag_from_echo is not None:

                        list_lag_echo = (lag_from_echo.group(3)).split('\n')
                        re_ports = re.compile("^(\s+port\s+(.*?)\s+)", re.MULTILINE | re.DOTALL)
                        list_lagports = []

                        for lag_echo in list_lag_echo:
                            l_ports = re_ports.search(lag_echo)
                            if l_ports is not None:
                                list_lagports.append((l_ports.group(2)).split('/'))
                        iom_count = 0
                        if list_lagports != []:
                            ports_count = {}
                            for lagport in list_lagports:
                                ports_count[lagport[0]] = lagport
                            iom_count = 0
                            for key in ports_count.keys():
                                iom_count += 1
                        saps_desc[sapnum].append(iom_count)

            vpls_conf[numvpls]['saps_profile'] = saps_desc
            # __DDS-13570 parse end___________________________________________

            vpls_conf[numvpls]['saps'] = saps

            # 1 - mesh found (True|False)
            mesh = re_mesh.findall(vpls)
            if mesh == []:
                vpls_conf[numvpls]['mesh_found'] = None
            else:
                vpls_conf[numvpls]['mesh_found'] = (mesh[0] == numvpls)

            # 2 - vpls no shutdown
            if not re_shut_vpls.search(vpls):
                vpls_conf[numvpls]['vpls_no_sh'] = True
            else:
                vpls_conf[numvpls]['vpls_no_sh'] = False

            # 3 - vpls descr
            if descvpls == []:
                vpls_conf[numvpls]['desc'] = ''
            else:
                vpls_conf[numvpls]['desc'] = descvpls[0]

            # 4 - mtu
            mtu_str = re_mtu.search(vpls)
            if mtu_str is not None:
                mtu = mtu_str.group('mtu')
                vpls_conf[numvpls]['mtu'] = mtu
            else:
                vpls_conf[numvpls]['mtu'] = '0'

            # 5 - mesh no shutdown
            mesh_no_sh = re_mesh_no_sh.search(vpls)
            if mesh_no_sh is not None:
                vpls_conf[numvpls]['mesh_no_sh'] = True
            else:
                vpls_conf[numvpls]['mesh_no_sh'] = False

            # 6 - bgp-vpls id
            ve_id = re_bgp_vpls.search(vpls)
            if ve_id is not None:
                ve_id = ve_id.group(1)
            else:
                ve_id = 'None'
            vpls_conf[numvpls]['ve_id'] = ve_id

            # 7 - re_monitor_oper_group
            monitor_oper_group = re_monitor_oper_group.search(vpls)
            if monitor_oper_group is not None:
                vpls_conf[numvpls]['monitor_oper_group'] = True
            else:
                vpls_conf[numvpls]['monitor_oper_group'] = False

        return vpls_conf

    # ______________DDS-13570__function check___
    def check_speed_on_descr_saps(saps_profile):
        result = {}
        saps = {}
        will_be_error_result = {}
        will_be_error_count = 0
        dimensions_speed = {
            'gbs': 1000000,
            'mbs': 1000,
            'kbs': 1,
            # 'bs' : 0.001
        }
        re_sapnum = re.compile("^(sap .+?)\s", re.MULTILINE | re.DOTALL)
        re_speed = re.compile("^(\s+description\s+\"(.*?)_CSPD_(.*?)_(.*?)\")", re.MULTILINE | re.DOTALL)

        re_rate_i = re.compile("^(\s+ingress(.*?))\s+rate\s+(\d+)", re.MULTILINE | re.DOTALL)
        re_rate_e = re.compile("^(\s+egress(.*?))\s+rate\s+(\d+)", re.MULTILINE | re.DOTALL)
        speeds = {}
        for key, sap_prof in saps_profile.items():
            sap_speed = re_speed.search(sap_prof[0])
            s_num = (re_sapnum.search(sap_prof[0])).group(1)
            result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 148001, result)
            if sap_speed is not None:
                ex = 0
                s_speed = sap_speed.group(3)
                speeds['desc_speed'] = s_speed
                try:
                    rate_i = int((re_rate_i.search(sap_prof[0])).group(3))
                    rate_e = int((re_rate_e.search(sap_prof[0])).group(3))
                    result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 148003, result)
                    if rate_i == rate_e:
                        # "all right, rate %s equivalents in %s" %(str(rate_i), str(s_num))
                        speeds['rate'] = rate_i
                    else:
                        result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 148003,
                                                     "On '%s' rate diffrent, ingress %s, egress %s" %
                                                     (str(s_num), str(rate_i), str(rate_e)), result)
                        speeds['rate'] = rate_i
                except Exception as ex:
                    print ex
                    ex = 1

                if ex == 0:
                    saps[s_num] = speeds
                    # "try is sucessful"
                    exect_speed = ''
                    exect_speed = re.sub(',', '.', re.sub(r'[A-Za-z]+', '', str(speeds['desc_speed'])))
                    if exect_speed != '':
                        desc_speed_kbs = 0
                        for dimens, coeff in dimensions_speed.items():
                            if dimens in str(speeds['desc_speed']).lower():
                                desc_speed_kbs = float(exect_speed) * coeff * (sap_prof[-1])
                                break
                        rate_speed = (re.sub(r'[\D]+', '', str(speeds['rate'])))
                        diff_coeff = 0
                        if rate_speed and (desc_speed_kbs != 0):
                            diff_coeff = ((float(desc_speed_kbs) / float(rate_speed)) * 100) - 100
                        result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 148003, result)
                        if (diff_coeff > 1) or (diff_coeff < -1):
                            diff_coeff = float("{0:.2f}".format(diff_coeff))
                            result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 148003,
                                                         "On '%s' diffrent speed between description='%s' and rate= '%s' (at iom=%s), is %s percents" %
                                                         (str(s_num), str(speeds['desc_speed']), str(rate_speed),
                                                          str(sap_prof[-1]), str(diff_coeff)), result)
                result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 148001, result)
                if (speeds['desc_speed']).lower() == 'max' and ((speeds['rate']).lower() != 'max'):
                    result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 148001,
                                                 " On '%s' listed speed is %s, but rate = %s " %
                                                 (str(s_num), str(speeds['desc_speed']), str(speeds['rate'])), result)

            else:
                # s_num, "has not correct speed in description, not contains trigger '_CSPD_' "
                will_be_error_result[str(s_num)] = "has not correct speed in description, not contains trigger '_CSPD_'"
                will_be_error_count += 1

                # WILL BE COMMENT!!!!
                # result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 148001,
                #                                        " '%s' has not correct speed in description, not contains trigger '_CSPD_' " %
                #                                        (str(s_num)), result)

                # WILL BE COMENT ^^^^^^^
                pass

        return result, will_be_error_count

    def check_bgp_vpls(all_bsrs_vpls):
        result = {}
        current_vpls = all_bsrs_vpls[mgmt.name]
        # ___________DDS-13570 call function check___________________________________
        all_no_cspd = 0
        for vpls in current_vpls:
            r, no_cspd = check_speed_on_descr_saps(
                current_vpls[vpls]['saps_profile'])  # there is dict {sap1:"block under", sap2:"block under"}
            all_no_cspd += no_cspd
            result = liboba.sum_results(result, r)
        # UNCOMMENTING
        result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 148001,
                                     " '%s' lags has not correct speed in description, not contains trigger '_CSPD_' " %
                                     (str(all_no_cspd)), result)
        # UNCOMMENTING ^^^^^
        result = liboba.add_descr_to_result(result,
                                            "<<<<< check speeds on description saps https://ticket.ertelecom.ru/browse/MSA-207 >>>>> (%d/%d)")
        # ____________DDS-13570 end check, end appends errors to result____________________________

        for vpls in current_vpls:
            if current_vpls[vpls]['ve_id'] == 'None':
                continue
            if current_vpls[vpls]['mesh_found'] is not None and current_vpls[vpls]['mesh_found']:
                result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 108033, result)
                if current_vpls[vpls]['mesh_no_sh']:
                    result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 108030, result)
                    if not current_vpls[vpls]['monitor_oper_group']:
                        result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 108030,
                                                     '[%s][vpls %s] mesh-sdp found but no monitor-oper-group "VRRP-3".' %
                                                     (str(mgmt), vpls), result)
                else:
                    result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 108033,
                                                 '[%s][vpls %s] mesh-sdp found but shutdown.' %
                                                 (str(mgmt), vpls), result)
            else:
                ve_ids = {}
                for bsr in all_bsrs_vpls:
                    if vpls not in all_bsrs_vpls[bsr]:
                        #                        result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 108031,
                        #                                                     '[%s][vpls %s] mesh-sdp nf, vpls nf on %s.' %
                        #                                                     (str(mgmt), vpls, bsr), result)
                        continue
                    ve_ids[bsr] = all_bsrs_vpls[bsr].get(vpls, {}).get('ve_id', None)
                for i, bsr in enumerate(ve_ids):
                    for j, bsr2 in enumerate(ve_ids):
                        if j <= i:
                            continue
                        local_ve_id = ve_ids[bsr]
                        other_ve_id = ve_ids[bsr2]
                        result = liboba.get_war_count(CHK_WRNG_CNST_ALU, 108032, result)
                        if other_ve_id == 'None' or local_ve_id == 'None' or other_ve_id == local_ve_id:
                            result = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 108032,
                                                         '[Current %s][Other %s][vpls %s] mesh-sdp nf, local ve-id = %s, other ve-id = %s. Both should exist and be not equal".' %
                                                         (bsr, bsr2, vpls, local_ve_id, other_ve_id), result)
        result = liboba.add_descr_to_result(result, "<<<<< check bgp-vpls >>>>> (%d/%d)")
        return result

    def all_bsrs_checks(all_bsrs_configs):
        result = {}
        all_bsrs_vpls = {}
        for bsr in all_bsrs_configs:
            all_bsrs_vpls[bsr] = get_vpls_dict_all_checks(all_bsrs_configs[bsr])
        r = check_bgp_vpls(all_bsrs_vpls)
        result = liboba.sum_results(result, r)

        return result

    # MSA-6345
    def check_dhcp_pool(structurized_conf, bras_name):
        """
        MSA-6345

        Check vprn 100 DHCP pool options in "Local DHCP Server (Services) Configuration" block.
        Options(subnet-mask and default-router) MUST match corresponding network mask and gw on
        subscriber-interface "SUB-DEFAULT" in "Service Configuration" block.
        Look at https://ticket.ertelecom.ru/browse/MSA-6345 for more details.

        Parameters
        ----------
        structurized_conf: dict
            Dictionary with results of libolga.main_1()
        bras_name: str
            BRAS name to check on.

        Returns
        -------
        dict[dict]
            Returns standart liboba result.
        """
        res = {}
        try:
            sub_default_addresses = (structurized_conf[bras_name]['echo "Service Configuration"']['service']
            ['vprns']['100']['setap_content']['subscriber_interfaces']
            ['SUB-DEFAULT']['addresses_and_gw'])
            vprn_100_dhcp_pools = (structurized_conf[bras_name]['echo "Local DHCP Server (Services) Configuration"']
            ['service']['100']['local_dhcp_servers']
            ['"DEFAULT-DHCP-ANYCAST"']['pools'])
        except KeyError:
            res = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 104045, "Can't get data to check pools.", res)
        except TypeError:
            res = liboba.get_war_desc(CHK_WRNG_CNST_ALU, 104045, "Wrong data structure. Can't check pools.", res)
        else:
            # Get all addresses with gateways from SUB-DEFAULT subscriber-interface.
            subscr_addresses = [
                IPv4WithGw(addr, gw_addr=attribs['gw_ip_ddn'])
                for addr, attribs in sub_default_addresses.items()
            ]
            for pool, pool_cont in vprn_100_dhcp_pools.items():
                # Check all subnets in pool.
                for subnet, subnet_cont in pool_cont['subnets'].items():
                    res = liboba.get_war_count(CHK_WRNG_CNST_ALU, 104045, res)
                    dr_ok = False
                    mask_ok = False
                    subnet_obj = ip.IPv4(subnet)
                    # There can be 2 or addresses from same subnet on subscriber-interface,
                    # so check all until match or no more to compare.
                    for subscr_addr in subscr_addresses:
                        # Check if subnets same.
                        if subnet_obj.normalized == subscr_addr.normalized:
                            # If yes - check if options correlate with subscriber-interface parameters.
                            options = subnet_cont['options']
                            if options:
                                if options['default-router'] == subscr_addr.gw_addr:
                                    dr_ok = True
                                if options['subnet_mask'] == subscr_addr.netmask.address:
                                    mask_ok = True
                                if dr_ok and mask_ok:
                                    # If got good match - no need to compare with others.
                                    break
                    if not all([dr_ok, mask_ok]):
                        res = liboba.get_war_desc(
                            CHK_WRNG_CNST_ALU, 104045,
                            'Wrong DHCP options: pool %s subnet %s,'
                            ' check corresponding address mask and gateway'
                            ' on SUB-DEFAULT subscriber-interface in vprn 100.' % (pool, subnet),
                            res
                        )
        res = liboba.add_descr_to_result(res, "<<<<< Check vprn 100 DHCP pools. >>>>> (%d/%d)")
        return res

    # ___REF_CONTINUE___
    print("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@")
    d_config = {}  # will be dict with changeover data of all config bsrs
    result_N = {}  # will be dict with errors of validations
    start = datetime.now()
    timestamp = datetime.now()

    print("1) start get names bsr")
    # get name of bsr from manage.object
    main_bras_name = ''
    main_bras_name = str(mgmt.name)
    if str(mgmt.get_attr('double_bras')) == 'None':
        double_bras_name = ''
    else:
        double_bras_name = str(mgmt.get_attr('double_bras'))
    print (1, (datetime.now() - timestamp))
    timestamp = datetime.now()

    print("2) start convert config to dict")
    d_config[main_bras_name] = libolga.main_1(config)  # writing to dict result library of parse main config
    d_config[main_bras_name]['TYPE'] = ['current']
    print (2, (datetime.now() - timestamp))
    timestamp = datetime.now()

    # TRY_GET_MAGIC_OCTET_one_on_city
    MO = '000'
    try:
        MO = str(int(mgmt.segment.settings['MO']))
    except:
        MO = str(int(mgmt.segment.settings.get('MO', 'SOME_DEFAULT')))

    print("3) start convert config to dict at the double bsr")
    flag_double_bras = 0
    if double_bras_name != '':
        # double bsr may be not declare in attribute
        try:
            # d_config['current']['NAME_BSR'] = main_bras_name
            mgmt2 = ManagedObject.objects.get(name=double_bras_name)
            config2 = mgmt2.config.get_gridvcs().get(mgmt2.id)
            d_config[double_bras_name] = libolga.main_1(
                config2)  # writing to dict result library of parse double config
            d_config[double_bras_name]['TYPE'] = 'double_bras'
            flag_double_bras = 1
            # d_config['double_bras']['NAME_BSR'] = double_bras_name
        except:
            flag_double_bras = 0
    print (3, (datetime.now() - timestamp))
    timestamp = datetime.now()

    print("4) start get_all_bsrs_configs_N")
    # (d_config[--current--]['NAME_BSR'], d_config[--double_bras--]['NAME_BSR'])
    all_bsrs_configs_N = get_all_bsrs_configs_N()  # now i dont know where it will be use
    for bsr_name, bsr_config in all_bsrs_configs_N.items():
        d_config[bsr_name] = libolga.main_1(bsr_config)
    print (4, (datetime.now() - timestamp))
    timestamp = datetime.now()

    print(d_config.keys())

    print("5) start check_si_and_sap_all_bsr")
    # chekc subscriber interface and sap(lag) on main and double bsrs #MSA-11
    # if d_config['double_bras'] != 'No double_bras':
    if flag_double_bras == 1:
        r_N = check_si_and_sap_all_bsr(d_config[main_bras_name]['echo "Service Configuration"']['service']['vprns'],
                                       d_config[double_bras_name]['echo "Service Configuration"']['service']['vprns'])
        result = liboba.sum_results(result, r_N)
    else:
        print ('NO DOUBLE BRAS!!!!')
    r = check_double_bras(d_config, main_bras_name, double_bras_name)
    result = liboba.sum_results(result, r)
    print (5, (datetime.now() - timestamp))
    timestamp = datetime.now()

    print("6) start single_checks_N")
    # single check main bras (only one) #MSA-1196
    r_N = single_checks_N(d_config[main_bras_name]['echo "System Configuration"'],
                          d_config[main_bras_name]['echo "Cron Configuration"'])
    result = liboba.sum_results(result, r_N)
    print (6, (datetime.now() - timestamp))
    timestamp = datetime.now()

    print("7) start  check_qos_sap_N")
    # check Network readiness for HLS #MSA-197
    r_N = check_qos_sap_N(d_config[main_bras_name]['echo "QoS Policy Configuration" DOUBLE']['qos']['saps'])
    result = liboba.sum_results(result, r_N)
    print (7, (datetime.now() - timestamp))
    timestamp = datetime.now()

    # temporary kostyl' NO DELETE
    with open('/opt/noc/lib/boba/test_olga/log_check_qos.txt', 'a') as local_log:
        # ("start writing to file")
        local_log.write(str(main_bras_name) + "\n")
        try:
            for err_N in r_N['errors']['MRI']['errors']:
                if err_N != {}:
                    local_log.write((err_N['message'] + "\n"))
            local_log.write("\n\n\n")
        except:
            local_log.write('No Result Validation QOS' + "\n\n\n")

    print("8) start check_prefixes_cctv")
    # CHECK_PREFIXES_AND_QOS_FOR_CCTV(MSA_190)
    try:
        ML_CCTV_SRV = \
            d_config[main_bras_name]['echo "Filter Match lists Configuration"']['filter_match_list']['"ML-CCTV-SRV"'][
                'prefixes']
        qos_300_in = \
            d_config[main_bras_name]['echo "QoS Policy Configuration" DOUBLE']['qos']['saps']['300']['ingress'][
                'ip_criteria']['entries']
        r_N = check_prefixes_cctv(ML_CCTV_SRV, qos_300_in)
        result = liboba.sum_results(result, r_N)
    except KeyError as key:
        print("AT THE CONFIG ERROR", key)
    print (8, (datetime.now() - timestamp))
    timestamp = datetime.now()

    # peny for latest result #(MSA-1196)
    qos_peny = 0
    for r_qos in r_N.get('errors', {}):
        qos_peny += r_N['errors'][r_qos]['peny']

    print("9) start check_ip_prefix_N")
    # prepared_to_all_bsrs_check
    ip_prefix_dict = {}
    for bsr_name in d_config.keys():
        # if bsr_name != '':
        try:
            ip_prefix_dict[bsr_name] = \
                d_config[bsr_name]['echo "Filter Match lists Configuration"']['filter_match_list']['"ML-MONITORING"'][
                    'prefixes']
        except Exception as ex:
            print("NO ML-MONITORING!!", ex)
    r_N = check_ip_prefix_N(ip_prefix_dict)
    result = liboba.sum_results(result, r_N)
    print (9, (datetime.now() - timestamp))
    timestamp = datetime.now()

    print("10) start check_endpoint_spoke_sdp")
    # prepared to check endpoint on vpls
    try:
        re_ip_double_bsr = re.compile('(^\s+peer\s+(?P<ip>\d+\.\d+\.\d+\.\d+)\s+create)', re.MULTILINE | re.DOTALL)
        founds_ip_double_bsr = re_ip_double_bsr.search(d_config[main_bras_name]['echo "Redundancy Configuration"'])
        ip_double_bsr = founds_ip_double_bsr.group('ip')
    except Exception as ex:
        ip_double_bsr = ''
        print('Error found ip double bras: %s' % (ex))
    # check endpoint spoke sdp               (https://ticket.ertelecom.ru/browse/MSA-5868)  + (https://ticket.ertelecom.ru/browse/MSA-6070)
    if flag_double_bras == 1:
        print("flag_double_bras == 1")
        r_N = check_endpoint_spoke_sdp(d_config[main_bras_name]['echo "Service Configuration"']['service']['vplss'],
                                       d_config[double_bras_name]['echo "Service Configuration"']['service']['vplss'],
                                       ip_double_bsr)
    else:
        print("flag_double_bras == 0")
        r_N = check_endpoint_spoke_sdp(d_config[main_bras_name]['echo "Service Configuration"']['service']['vplss'], {},
                                       ip_double_bsr)
    result = liboba.sum_results(result, r_N)
    print (10, (datetime.now() - timestamp))
    timestamp = datetime.now()

    print("11) start check_ifaces_N")
    # check_ifaces_oters
    r_N = check_ifaces_N(d_config[main_bras_name]['echo "Service Configuration"']['service']['vprns'])
    result = liboba.sum_results(result, r_N)
    print (11, (datetime.now() - timestamp))
    timestamp = datetime.now()

    print("12) start check_vrrp_on_vprns")
    # check_vrrp_vprn
    r_N = check_vrrp_on_vprns(d_config[main_bras_name]['echo "Service Configuration"']['service']['vprns'])
    result = liboba.sum_results(result, r_N)
    print (12, (datetime.now() - timestamp))
    timestamp = datetime.now()

    print("13) start converter(d_config[main_bras_name]")
    iface_M = libolga.converter(d_config[main_bras_name])
    print (13, (datetime.now() - timestamp))
    timestamp = datetime.now()

    print("14) start liboba.check_ifacedesc(iface_M)")
    r_M, iface_M = liboba.check_ifacedesc(iface_M)
    result = liboba.sum_results(result, r_M)
    print (14, (datetime.now() - timestamp))
    timestamp = datetime.now()

    print("015) start check_pools_blackhole")
    # parse dhcp pools
    try:
        dhcp_part_config = d_config[main_bras_name]['echo "Local DHCP Server (Services) Configuration"']['FULL']
    except Exception as ex:
        print(ex)
        dhcp_part_config = ''
    dhcp_servers, dhcp_configs = parse_dhcp_servers(dhcp_part_config)
    static_routes = \
        d_config[main_bras_name]['echo "Service Configuration"']['service']['vprns']['100']['setap_content'][
            'static_route_entry']
    # dhcp_servers, dhcp_configs = parse_dhcp_servers(config)
    # static_routes = parse_static_routes(config)		#REF to libolga

    # check pools in static routes
    r = check_pools_blackhole(d_config[main_bras_name]['echo "Redundancy Configuration"'], dhcp_servers, static_routes,
                              dhcp_configs)
    result = liboba.sum_results(result, r)
    print (15, datetime.now() - timestamp)
    timestamp = datetime.now()

    print("016) start check_sub_default(dhcp_servers, config, ifaces)")
    try:
        sub_defaults_config = (d_config[main_bras_name]['echo "Service Configuration"']['service']['vprns']['100'][
                                   'declare_content']['subscriber_interfaces']['SUB-DEFAULT']['content'] +
                               d_config[main_bras_name]['echo "Service Configuration"']['service']['vprns']['100'][
                                   'setap_content']['subscriber_interfaces']['SUB-DEFAULT']['content'])
    except Exception as ex:
        print(ex)
        sub_defaults_config = ''
    r = check_sub_default(dhcp_servers, sub_defaults_config, static_routes, iface_M)
    result = liboba.sum_results(result, r)
    print (16, datetime.now() - timestamp)
    timestamp = datetime.now()
    # ----REF_END___

    # ********************************
    print("TEMPORARY) start parse_interfaces")
    # parse ports
    ifaces = parse_interfaces(config)

    r, ifaces = liboba.check_ifacedesc(ifaces)
    # result = liboba.sum_results(result, r)

    r = check_ifaces(ifaces)
    # result = liboba.sum_results(result, r)

    gifaces, ifaces = parse_gifaces(config, ifaces)

    # **********************************

    print("019) start liboba.get_other_devs(mgmt)")
    # get configs from other alu
    bsrs = liboba.get_other_devs(mgmt)
    # print 10, datetime.now() - timestamp
    # timestamp = datetime.now()
    # check pools in other alu
    print("020) start check_other_bsr_pools(bsrs, dhcp_servers)")
    r = check_other_bsr_pools(bsrs, dhcp_servers)
    result = liboba.sum_results(result, r)
    # print 11, datetime.now() - timestamp
    # timestamp = datetime.now()

    # check pools in static routes other alu
    print("021) start check_other_bsr_static(bsrs, dhcp_servers)")
    r = check_other_bsr_static(bsrs, dhcp_servers)
    result = liboba.sum_results(result, r)
    # print 12, datetime.now() - timestamp
    # timestamp = datetime.now()

    # parse PL
    print("022) start parse_pl(config)")
    pls = parse_pl(config)
    # check PL-SPEC in PL-GENERAL

    print("023) start liboba.check_spec_general(pls)")
    r = liboba.check_spec_general(pls)
    result = liboba.sum_results(result, r)
    # print 13, datetime.now() - timestamp
    # timestamp = datetime.now()

    # parse all static routes from all alu
    print("024) start astatic_routes")
    astatic_routes = dict(static_routes.items() + parse_all_static_routes(bsrs).items())
    # print 14, datetime.now() - timestamp
    # timestamp = datetime.now()

    # check PL-SPEC in all static routes
    print("025) start check_spec_blackhole")
    r = liboba.check_spec_blackhole(pls, astatic_routes)
    result = liboba.sum_results(result, r)
    # print 15, datetime.now() - timestamp
    # timestamp = datetime.now()

    # check PL-GENERAL in all static routes
    print("026) start liboba.check_general_blackhole")
    r = liboba.check_general_blackhole(pls, static_routes)
    result = liboba.sum_results(result, r)
    # print 16, datetime.now() - timestamp
    # timestamp = datetime.now()

    # parse PL-GENERAL-SPEC
    print("027) start parse_pl_general_spec(config)")
    pls2 = parse_pl_general_spec(config)
    # print 17, datetime.now() - timestamp
    # timestamp = datetime.now()

    # check PL-GENERAL-SPEC
    print("028) start check_pl_general_spec(pls, pls2)")
    r = check_pl_general_spec(pls, pls2)
    result = liboba.sum_results(result, r)
    # print 18, datetime.now() - timestamp
    # timestamp = datetime.now()

    # parse subscriber-interfaces
    print("029) start parse_sifaces(config)")
    sifaces = parse_sifaces(config)
    # print 19, datetime.now() - timestamp
    # timestamp = datetime.now()
    # check subscribers-interfaces (names)
    print("030) start check_sifaces(sifaces)")
    r = check_sifaces(sifaces)
    result = liboba.sum_results(result, r)
    # print 20, datetime.now() - timestamp
    # timestamp = datetime.now()

    # parse groupe-interface
    # print("031) start gifaces, ifaces = parse_gifaces(config, ifaces)")
    # gifaces, iface_M_M = parse_gifaces(config, iface_M)
    # print 21, datetime.now() - timestamp
    # timestamp = datetime.now()

    misccheck = [
        # (100001,True,'entry 120\n                    match "configure service vprn shutdown"\n                    action deny\n                exit\n                entry 130\n                    match "configure service vprn dhcp local-dhcp-server shutdown"\n                    action deny\n                exit\n                entry 140\n                    match "configure service vprn subscriber-interface shutdown"\n                    action deny\n                exit'),
        # (100002,True,'password\n                authentication-order exit-on-reject\n'),
        (100009, True,
         'entry 120\n                    match "configure service vprn shutdown"\n                    action deny\n                exit'),
        (100009, True,
         'entry 130\n                    match "configure service vprn dhcp local-dhcp-server shutdown"\n                    action deny\n                exit'),
        (100009, True,
         'entry 140\n                    match "configure service vprn subscriber-interface shutdown"\n                    action deny\n                exit'),
        (100009, True,
         'entry 150\n                    match "configure service vprn bgp shutdown"\n                    action deny\n                exit'),
        (100009, True,
         'entry 160\n                    match "configure service vprn subscriber-interface group-interface shutdown"\n                    action deny\n                exit'),
        (100009, False,
         'vpls 2 customer 1 m-vpls create\n            shutdown\n'),
    ]
    # misc checks
    print("032) start liboba.check_misc")
    r = liboba.check_misc(config, misccheck, CHK_WRNG_CNST_ALU)
    result = liboba.sum_results(result, r)
    # print 22, datetime.now() - timestamp
    # timestamp = datetime.now()

    # check groupe-interface (saps)

    print("033) start check_gifaces(gifaces, gifaces, '')")
    print(type(gifaces))
    print(len(gifaces))
    r = check_gifaces(gifaces, gifaces, '')
    result = liboba.sum_results(result, r)
    # print 23, datetime.now() - timestamp
    # timestamp = datetime.now()

    # check sap from curent alu on other alu
    print("034) start check_other_bsr_gifaces(bsrs, gifaces)")
    r = check_other_bsr_gifaces(bsrs, gifaces)
    result = liboba.sum_results(result, r)
    # print 24, datetime.now() - timestamp
    # timestamp = datetime.now()

    # check all saps on lag
    r = check_saps()
    result = liboba.sum_results(result, r)
    # print 25, datetime.now() - timestamp
    # timestamp = datetime.now()

    # parse ips
    ips = liboba.parse_ip(config)
    # print 26, datetime.now() - timestamp
    # timestamp = datetime.now()

    # check ips
    r = liboba.check_ips(ips)
    result = liboba.sum_results(result, r)
    # print 27, datetime.now() - timestamp
    # timestamp = datetime.now()

    # check qos
    r = check_qos(config, ifaces)
    result = liboba.sum_results(result, r)
    # print 28, datetime.now() - timestamp
    # timestamp = datetime.now()

    # MSA-6059
    skip_filter_check_ifaces = get_skip_filter_check_ifaces(d_config, main_bras_name)
    r = check_filters(config, ifaces, skip_filter_check_ifaces)
    result = liboba.sum_results(result, r)

    # check sap filters
    # print 29, datetime.now() - timestamp
    # timestamp = datetime.now()

    # check port mtu
    r = check_mtu(ifaces)
    result = liboba.sum_results(result, r)
    # print 30, datetime.now() - timestamp
    # timestamp = datetime.now()

    # parse msap-policy
    mp_cfg = parse_msap_policy(config)
    # print 31, datetime.now() - timestamp
    # timestamp = datetime.now()

    # check msap-policy
    r = check_msap_policy(mp_cfg)
    result = liboba.sum_results(result, r)
    # print 32, datetime.now() - timestamp
    # timestamp = datetime.now()

    # check mda sap resource optimizations on access lag
    r = check_mda_resource_optimization(ifaces)
    result = liboba.sum_results(result, r)
    # print 33, datetime.now() - timestamp
    # timestamp = datetime.now()

    r = check_pado_polices(config)
    result = liboba.sum_results(result, r)
    # print 34, datetime.now() - timestamp
    # timestamp = datetime.now()

    r = check_ludb(config)
    result = liboba.sum_results(result, r)
    # print 35, datetime.now() - timestamp
    # timestamp = datetime.now()

    r = rateindavpls_check(d_config[main_bras_name]['echo "Service Configuration"']['service']['vplss'])
    result = liboba.sum_results(result, r)
    # print 36, datetime.now() - timestamp
    # timestamp = datetime.now()

    # check vpls saps inner tags
    r = check_vpls_saps_inner_tags(config)
    result = liboba.sum_results(result, r)
    # print 38, datetime.now() - timestamp
    # timestamp = datetime.now()

    # check cmp_filter
    # if 'bryansk' in mgmt.name:
    r = check_cpm_filter(config)
    result = liboba.sum_results(result, r)
    # print 39, datetime.now() - timestamp
    # timestamp = datetime.now()

    # check cmp_filter
    # if 'kirov' in mgmt.name:
    r = check_ipfilter(config)
    result = liboba.sum_results(result, r)
    # print 40, datetime.now() - timestamp
    # timestamp = datetime.now()

    # check pools with drain
    r = check_pools_with_drain(config)
    result = liboba.sum_results(result, r)
    # print 41, datetime.now() - timestamp
    # timestamp = datetime.now()

    # check filter_90
    if 'bryansk' in mgmt.name:
        r = check_filter_90(config)
        result = liboba.sum_results(result, r)
        # print 41.5, datetime.now() - timestamp
        # timestamp = datetime.now()

    r = check_raddb(config)
    result = liboba.sum_results(result, r)
    print (42, datetime.now() - timestamp)
    timestamp = datetime.now()

    r = check_ipoe_pools(config)
    result = liboba.sum_results(result, r)
    print (43, datetime.now() - timestamp)
    timestamp = datetime.now()

    all_bsrs_configs = get_all_bsrs_configs()
    print (44, datetime.now() - timestamp)
    timestamp = datetime.now()

    r = all_bsrs_checks(all_bsrs_configs)
    result = liboba.sum_results(result, r)
    print (45, datetime.now() - timestamp)
    timestamp = datetime.now()

    # check IPTV DDS-10914
    r = check_iptv(config)
    result = liboba.sum_results(result, r)
    print (46, datetime.now() - timestamp)
    timestamp = datetime.now()

    # MSA-6345
    r = check_dhcp_pool(d_config, main_bras_name)
    result = liboba.sum_results(result, r)

    print ('total', datetime.now() - start)

    total_peny = 0
    iptv_peny = 0
    total_message = []
    for ra in r.get('errors', {}):
        iptv_peny += r['errors'][ra]['peny']

    print(mgmt.segment.settings['MO'])

    return {'qos_peny': qos_peny, 'iptv_peny': iptv_peny, 'result': result}
