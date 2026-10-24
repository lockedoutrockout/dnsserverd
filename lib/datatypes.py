"""
lib/datatypes.py

Custom datatype definitions
"""

import os
import sys
import subprocess
import socket
from pathlib import Path
from dnslib import DNSRecord, QTYPE, RR, A, ZoneParser
from dnslib.server import DNSServer as DNSLibDNSServer
from dnslib.server import DNSHandler, BaseResolver
from . import exceptions

"""
Override Record Dictionary Structure:

record = {
    "id": 1, # Unique identifier for the record
    "category": "override", # Category. States whether the record is an override or a zone record
    "scope": "global", # Scope. States what this record is applicable to. Can be 'global' for a globally scoped record or an IP address for a specific client
    "rr": <RR object at...>, # An active RR object instance built from the record
    "rtype": "A", # States what type of DNS record this is
    "rname": "example.com", # Specifies the domain/host name to be overridden
    "rdata": "192.168.0.1", # Contains the falsified data the server will respond to the query with
    "ttl": 60 # Length of time which the response remains valid for
}
"""

def dict_to_rr(d):
    """ Convert a dictionary into an RR object
    """
    c = (
        f"{d['qname']} "
        f"{d.get('ttl', 60)} "
        f"IN "
        f"{d['rtype']} "
        f"{d['rdata']}"
    )
    return next(RR.fromZone(c))

def rr_to_dict(r):
    """ Convert an RR object into a dictionary
    """
    c = {
        "rclass": r.rclass,
        "rtype": QTYPE[r.rtype],
        "rname": str(r.rname),
        "rdata": str(r.rdata),
        "ttl": r.ttl
    }
    return c

def resolve_host(host):
    """ Resolve a hostname into an IP address
    """
    try:
        return socket.gethostbyname(host)
    except socket.gaierror as err_msg:
        raise err_msg

class DoHBlocklist(object):
    """ DNS-over-HTTPS host blocklist
    """
    def __init__(self, config=None, logger=None):
        self.doh_blocklist = []
        self.update_thread = None
        self.is_updating = False
        self.doh_hosts_file = self.config["EXPLOITATION"]["doh_hosts_filepath"]
        if "~" in self.doh_hosts_file:
            self.doh_hosts_file = os.path.expanduser(self.doh_hosts_file)
        if os.path.isfile(self.doh_hosts_file):
            with open(self.doh_hosts_file, "r") as fd:
                hosts = []
                for line in fd.readlines():
                    hosts.append(line.strip())
            self.update_doh_blocklist(hosts)
            if self.is_updating:
                self.update_thread.join()
        else:
            Path(self.doh_hosts_file).touch()

    def update_doh_blocklist(self, hosts, append):
        """ Update the DoH blocklist
        """
        def _update_thread(hosts):
            """ DoH blocklist updater thread
            """
            self.is_updating = True
            doh_blocklist = []
            for host in hosts:
                try:
                    doh_blocklist.append((host, resolve_host(host)))
                except Exception as err_msg:
                    raise exceptions.DNSFirewallError(f"Encountered an unexpected exception while updating the DoH blocklist") from err_msg
            if not append:
                self.doh_blocklist.clear()
            self.doh_blocklist.extend(doh_blocklist)
            self.is_updating = False
            return None

        self.update_thread = threading.Thread(target=_update_thread, args=(hosts,), daemon=True)
        self.update_thread.start()
        return None

class DNSRecordList(object):
    """ A categorized and sorted master list of DNS records
    """
    def __init__(self, config=None, logger=None):
        self.config = config
        self.logger = logger
        self.records = {
            "all": [],
            "by_category": {
                "zone": [],
                "override": []
            },
            "by_scope": {
                "global": []
            },
            "by_rtype": {
                "SOA": [],
                "NS": [],
                "A": [],
                "AAAA": [],
                "CNAME": [],
                "MX": [],
                "TEXT": []
            },
            "by_rname": {},
            "by_rdata": {},
            "by_ttl": {}
        }
        self.zone_records_file = self.config["DNS"]["zone_records_filepath"]
        if "~" in self.zone_records_file:
            self.zone_records_file = os.path.expanduser(self.zone_records_file)
        if os.path.isfile(self.zone_records_file):
            self.import_zone_file(self.zone_records_file, "zone", "global")
        else:
            self.gen_dns_zonefile(self.zone_records_file)
        self.override_records_file = self.config["EXPLOITATION"]["override_records_filepath"]
        if "~" in self.override_records_file:
            self.override_records_file = os.path.expanduser(self.override_records_file)
        if os.path.isfile(self.override_records_file):
            self.import_zone_file(self.override_records_file, "override", "global")
        else:
            Path(self.override_records_file).touch()

    def gen_dns_zonefile(self, outfile):
        """ Generate a zonefile for the local DNS zone
        """
        pass

    def search_by_id(self, id_):
        """ Get record by its ID
        """
        for record in self.records["all"]:
            if record["id"] == id_:
                return record
        return None

    def import_zone_file(self, infile, category, scope):
        """ Import records from a DNS zonefile
        """
        if not os.path.isfile(infile):
            raise exceptions.DNSRecordListError(f"Cannot import records from zonefile! File does not exist: {infile}")
        if category not in ("zone", "override"):
            raise exceptions.DNSRecordListError(f"Cannot import records from zonefile! Invalid category: {category}")

        with open(infile, "r") as fd:
            try:
                zone_parser = ZoneParser(fd)
                rr_records = list(zone_parser.parse())
            except Exception as err_msg:
                raise exceptions.DNSRecordListError(f"Encountered an unexpected exception while importing records from zonefile: {infile}") from err_msg

        ids = []
        for rr_record in rr_records:
            rdict = rr_to_dict(rr_record)
            id_ = self.add_record(
                category,
                scope,
                rdict["rtype"],
                rdict["rname"],
                rdict["rdata"],
                rdict["ttl"]
            )
            ids.append(id_)

        return ids

    def export_zone_file(self, outfile, category, scope):
        """ Export records to a DNS zonefile
        """
        if category not in ("zone", "override"):
            raise exceptions.DNSRecordListError(f"Cannot export records to zonefile! Invalid category: {category}")
        if scope != "all" and scope not in self.records["by_scope"].keys():
            raise exceptions.DNSRecordListError(f"Cannot export records to zonefile! Invalid scope: {scope}")

        if scope == "all":
            rl = self.records["all"]
        else:
            rl = self.records["by_scope"][scope]
        records = []
        for record in rl:
            if record["category"] == category:
                records.append(record)

        with open(outfile, "w") as fd:
            for record in records:
                fd.write(f"{record['rr']}\n")

        return None

    def add_record(self, category, scope, rtype, rname, rdata, ttl):
        """ Adds a new record
        """
        id_ = len(self.records["all"]) + 1
        while self.search_by_id(id_) is not None:
            id_ += 1
        record = {
            "id": id_,
            "category": category,
            "scope": scope,
            "rtype": rtype,
            "rname": rname,
            "rdata": rdata,
            "ttl": ttl
        }
        rr = dict_to_rr(record)
        record["rr"] = rr

        self.records["all"].append(record)
        if record["category"] not in self.records["by_category"].keys():
            self.records["by_category"][record["category"]] = []
        self.records["by_category"][record["category"]].append(record)
        if record["scope"] not in self.records["by_scope"].keys():
            self.records["by_scope"][record["scope"]] = []
        self.records["by_scope"][record["scope"]].append(record)
        if record["rtype"] not in self.records["by_rtype"].keys():
            self.records["by_rtype"][record["rtype"]] = []
        self.records["by_rtype"][record["rtype"]].append(record)
        if record["rname"] not in self.records["by_rname"].keys():
            self.records["by_rname"][record["rname"]] = []
        self.records["by_rname"][record["rname"]].append(record)
        if record["rdata"] not in self.records["by_rdata"].keys():
            self.records["by_rdata"][record["rdata"]] = []
        self.records["by_rdata"][record["rdata"]].append(record)
        if record["ttl"] not in self.records["by_ttl"].keys():
            self.records["by_ttl"][record["ttl"]] = []
        self.records["by_ttl"][record["ttl"]].append(record)

        return record

    def remove_record(self, id_):
        """ Remove an existing record
        """
        if not self.search_by_id(id_):
            raise exceptions.RecordNotFoundError(f"Could not find a DNS record with ID of: {id_}")
            
        record = self.search_by_id(id_)
        self.records["all"].remove(record)
        self.records["by_category"][record["category"]].remove(record)
        self.records["by_scope"][record["scope"]].remove(record)
        self.records["by_rtype"][record["rtype"]].remove(record)
        self.records["by_rname"][record["rname"]].remove(record)
        self.records["by_rdata"][record["rdata"]].remove(record)
        self.records["by_ttl"][record["ttl"]].remove(record)

        return record

class DNSFirewall(object):
    """ Handles tasks related to enforcing use of the DNS server
    by network clients
    """
    def __init__(self, settings, config=None, logger=None):
        self.config = config
        self.logger = logger
        self.settings = settings
        self.dns_redirection(self.settings["RedirectDNSTraffic"])
        self.quic_blocking(self.settings["BlockQUIC"])
        self.doh_blocking(self.settings["BlockDoH"])

        return None

    def dns_redirection(self, enable):
        """ Enable/disable DNS traffic redirection
        """
        if enable:
            try:
                subprocess.run([
                    "iptables",
                    "-t",
                    "nat",
                    "-A",
                    "PREROUTING",
                    "-i",
                    self.config["SERVER"]["interface"],
                    "-p",
                    "udp",
                    "--dport",
                    "53",
                    "-j",
                    "DNAT",
                    "--to-destination",
                    f"{self.settings['DNSRedirectTargetIP']}:53")
                ])
                subprocess.run([
                    "iptables",
                    "-t",
                    "nat",
                    "-A",
                    "PREROUTING",
                    "-i",
                    self.config["SERVER"]["interface"],
                    "-p",
                    "tcp",
                    "--dport",
                    "53",
                    "-j",
                    "DNAT",
                    "--to-destination",
                    f"{self.settings['DNSRedirectTargetIP']}:53")
                ])
            except Exception as err_msg:
                raise exceptions.DNSFirewallError(f"Encountered an unexpected exception while enabling DNS traffic redirection") from err_msg
        else:
            try:
                subprocess.run([
                    "iptables",
                    "-t",
                    "nat",
                    "-D",
                    "PREROUTING",
                    "-i",
                    self.config["SERVER"]["interface"],
                    "-p",
                    "udp",
                    "--dport",
                    "53",
                    "-j",
                    "DNAT",
                    "--to-destination",
                    f"{self.settings['DNSRedirectTargetIP']}:53")
                ])
                subprocess.run([
                    "iptables",
                    "-t",
                    "nat",
                    "-D",
                    "PREROUTING",
                    "-i",
                    self.config["SERVER"]["interface"],
                    "-p",
                    "tcp",
                    "--dport",
                    "53",
                    "-j",
                    "DNAT",
                    "--to-destination",
                    f"{self.settings['DNSRedirectTargetIP']}:53")
                ])
            except Exception as err_msg:
                raise exceptions.DNSFirewallError(f"Encountered an unexpected exception while disabling DNS traffic redirection") from err_msg
        return None

    def quic_blocking(self, enable):
        """ Block/unblock QUIC traffic
        """
        if enable:
            try:
                subprocess.run([
                    "iptables",
                    "-A",
                    "FORWARD",
                    "-i",
                    self.config["SERVER"]["interface"],
                    "-p",
                    "udp",
                    "--dport",
                    "443",
                    "-j",
                    "DROP"
                ])
                self.quic_blocking_enabled = True
            except Exception as err_msg:
                raise exceptions.DNSFirewallError(f"Encountered an unexpected exception while enabling QUIC traffic blocking") from err_msg
        else:
            try:
                subprocess.run([
                    "iptables",
                    "-D",
                    "FORWARD",
                    "-i",
                    self.config["SERVER"]["interface"],
                    "-p",
                    "udp",
                    "--dport",
                    "443",
                    "-j",
                    "DROP"
                ])
                self.quic_blocking_enabled = False
            except Exception as err_msg:
                raise exceptions.DNSFirewallError(f"Encountered an unexpected exception while disabling QUIC traffic blocking") from err_msg
        return None

    def doh_blocking(self, enable):
        """ Block/unblock DNS-over-HTTPS traffic
        """
        if enable:
            try:
                subprocess.run([
                    "ipset",
                    "create",
                    "doh_blocklist",
                    "hash:ip"
                ])
                for host in self.doh_blocklist:
                    subprocess.run([
                        "ipset",
                        "add",
                        "doh_blocklist",
                        host[1]
                    ])
                subprocess.run([
                    "iptables",
                    "-A",
                    "FORWARD",
                    "-i",
                    self.config["SERVER"]["interface"],
                    "-p",
                    "tcp",
                    "-m",
                    "set",
                    "--match-set",
                    "doh_blocklist",
                    "dst",
                    "--dport",
                    "443",
                    "-j",
                    "DROP"
                ])
                self.doh_blocking_enabled = True
            except Exception as err_msg:
                raise exceptions.DNSFirewallError(f"Encountered an unexpected exception while enabling DoH blocking") from err_msg
        else:
            try:
                subprocess.run([
                    "iptables",
                    "-D",
                    "OUTPUT",
                    "-p",
                    "tcp",
                    "-m",
                    "set",
                    "--match-set",
                    "doh_blocklist",
                    "dst",
                    "--dport",
                    "443",
                    "-j",
                    "DROP"
                ])
                subprocess.run([
                    "ipset",
                    "flush",
                    "doh_blocklist"
                ])
                self.doh_blocking_enabled = False
            except Exception as err_msg:
                raise exceptions.DNSFirewallError(f"Encountered an unexpected exception while disabling DoH blocking") from err_msg

class DNSResolver(object):
    """ Custom DNS resolver
    """
    def __init__(self, settings, dns_records, config=None, logger=None):
        self.config = config
        self.logger = logger
        self.settings = settings
        self.dns_records = dns_records

    def resolve(self, request, handler):
        """ Resolve DNS queries
        """
        def normalize(name):
            """ Domain name normalization
            """
            return name.lower().rstrip(".") + "."

        def wildcard_match(qname, rname):
            """ Wildcard record matching
            """
            if not rname.startswith("*."):
                return False
            suffix = rname[2:]
            if not qname.endswith(suffix):
                return False
            qlabels = qname.rstrip(".").split(".")
            slabels = suffix.rstrip(".").split(".")
            if len(qlabels) == len(slabels) + 1:
                return True
            else:
                return False

        qname = normalize(str(request.q.qname).rstrip("."))
        qtype = QTYPE[request.q.qtype]
        client_ip = handler.client_address[0]
        reply = request.reply()

        # Resolve with override records
        if self.dns_records["by_category"]["override"]:
            exact_matches = []
            wildcard_matches = []
            for record in self.dns_records["by_category"]["override"]:
                # Continue to the next record unless record is globally scoped or scoped to the client's IP
                if record["scope"] != "global":
                    if record["scope"] != client_ip:
                        continue
                rr = record["rr"]
                if qtype not in (QTYPE[rr.rtype], "ANY"):
                    continue
                if qname == normalize(str(rr.rname)):
                    exact_matches.append(rr)
                elif wildcard_match(qname, normalize(str(rr.rname))):
                    wildcard_matches.append(rr)
            matches = exact_matches or wildcard_matches
            if matches:
                for rr in matches:
                    reply.add_answer(rr)
                self.logger.info(f"Responding to query for {qname} from {client_ip} with response from override records")
                return reply

        # Resolve with zone records
        if self.dns_records["by_category"]["zone"]:
            for record in self.dns_records["by_category"]["zone"]:
                rr = record["rr"]
                if qtype in (QTYPE[rr.rtype], "ANY") and qname == normalize(str(rr.rname)):
                    reply.add_answer(rr)
                    reply.header.aa = 1
                    self.logger.info(f"Responding to query for {qname} from {client_ip} with response from zone records")
                    return reply

        # Resolve with upstream resolvers
        for upstream in (self.settings["PrimaryUpstream"], self.settings["BackupUpstream"]):
            try:
                upstream_response = request.send(upstream, 53, tcp=False)
                self.logger.info(f"Responding to query for {qname} from {client_ip} with response from upstream resolver")
                return DNSRecord.parse(upstream_response)
            except Exception as err_msg:
                self.logger.error(f"Got error resolving query through upstream server: {err_msg}")\
                continue

class DNSServer(object):
    """ DNS server backend
    """
    def __init__(self, config=None, logger=None):
        self.config = config
        self.logger = logger
        self.processes = {}
        self.state = "not running"
        self.dns_records = DNSRecordList(config=self.config, logger=self.logger)
        self.doh_blocklist = DoHBlocklist(config=self.config, logger=self.logger) 
        self.settings = {
            "UseTCP": self.config.getboolean("SERVER", "use_tcp"),
            "PrimaryUpstream": self.config["DNS"]["primary_upstream"],
            "BackupUpstream": self.config["DNS"]["backup_upstream"],
            "DNSRedirectTargetIP": self.config["EXPLOITATION"]["dns_redirect_target_ip"],
            "RedirectDNSTraffic": self.config.getboolean("EXPLOITATION", "redirect_dns_traffic"),
            "BlockQUIC": self.config.getboolean("EXPLOITATION", "block_quic"),
            "BlockDoH": self.config.getboolean("EXPLOITATION", "block_doh")
        }
        self._settings = {
            "UseTCP": self.config.getboolean("DNS", "use_tcp"),
            "PrimaryUpstream": self.config["DNS"]["primary_upstream"],
            "BackupUpstream": self.config["DNS"]["backup_upstream"],
            "DNSRedirectTargetIP": self.config["EXPLOITATION"]["dns_redirect_target_ip"],
            "RedirectDNSTraffic": self.config.getboolean("EXPLOITATION", "redirect_dns_traffic"),
            "BlockQUIC": self.config.getboolean("EXPLOITATION", "block_quic"),
            "BlockDoH": self.config.getboolean("EXPLOITATION", "block_doh")
        }

    def _Start(self):
        """ Start the process
        """
        if self.state == "running":
            raise exceptions.StateChangeError(f"DNS server is already running")
        try:
            self.state = "starting"
            resolver = DNSResolver(
                self.settings,
                self.dns_records,
                config=self.config,
                logger=self.logger
            )
            self.server = DNSLibDNSServer(resolver, port=int(self.config["DNS"]["lport"]), address=self.config["DNS"]["laddr"])
            self.server.start_thread()
        except Exception as err_msg:
            self.state = "startup failed"
            raise err_msg
        self.state = "running"
        return None

    def _Stop(self):
        """ Stop the process
        """
        if self.state == "not running":
            raise exceptions.StateChangeError(f"Template is not running")
        try:
            self.state = "stopping"
            self.server.stop()
        except Exception as err_msg:
            self.state = "shutdown failed"
            raise err_msg
        self.state = "not running"
        return None

    def _Restart(self):
        """ Restart the process
        """
        if self.state == "not running":
            raise exceptions.StateChangeError(f"Process is not running")
        try:
            self._Stop()
            self._Start()
        except Exception as err_msg:
            self.state = "restart failed"
            raise err_msg
        return None

    def _ApplyConfiguration(self):
        """ Apply new configuration settings
        """
        self.settings = self._settings
        try:
            pass
        except Exception as err_msg:
            self.state = "apply configuration failed"
            raise err_msg
        return None

    def _UpdateDoHBlocklist(self, hosts, append):
        """ Update the DoH host blocklist
        """
        try:
            self.doh_blocklist.update_doh_blocklist(hosts, append)
        except Exception as err_msg:
            raise err_msg
        return None

    def _ImportZoneFile(self, infile, category, scope):
        """ Import DNS records from a zonefile
        """
        try:
            ids = self.dns_records.import_zone_file(infile, category, scope)
        except Exception as err_msg:
            raise err_msg
        return ids

    def _ExportZoneFile(self, outfile, category, scope):
        """ Export DNS records to a zonefile
        """
        try:
            self.dns_records.export_zone_file(outfile, category, scope)
        except Exception as err_msg:
            raise err_msg
        return None

    def _AddDNSRecord(self, category, scope, rtype, rname, rdata, ttl):
        """ Add a new DNS override record
        """
        try:
            id_ = self.dns_records.add_record(category, scope, rtype, rname, rdata, ttl)
        except Exception as err_msg:
            raise err_msg
        return id_

    def _RemoveDNSRecord(self, id_):
        """ Remove an existing DNS override record
        """
        try:
            self.dns_records.remove_record(id_)
        except Exception as err_msg:
            raise err_msg
        return None
