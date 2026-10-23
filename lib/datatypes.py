"""
lib/datatypes.py

Custom datatype definitions
"""

import os
import sys
import subprocess
from dnslib import DNSRecord, QTYPE, RR, A, ZoneParser
from dnslib.server import DNSServer as DNSLibDNSServer
from dnslib.server import DNSHandler, BaseResolver
from . import exceptions

def dict_to_rr(record):
    """ Convert a DNS record dictionary into an RR object
    """
    zr = (
        f"{record['qname']} "
        f"{record.get('ttl', 60)} "
        f"IN "
        f"{record['rtype']} "
        f"{record['rdata']}"
    )
    return next(RR.fromZone(zr))

class DNSResolver(object):
    """ Custom DNS resolver
    """
    def __init__(self, settings, doh_blocklist, override_records, config=None, logger=None):
        self.config = config
        self.logger = logger
        self.settings = settings
        self.doh_blocklist = doh_blocklist
        self.override_records = override_records
        if os.path.isfile(self.config["ZONE"]["zone_file"]):
            with open(self.config["ZONE"]["zone_file"], "r") as fd:
                zp = ZoneParser(fd)
                self.zone_records = list(zp.parse())

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

        if self.override_records:
            exact_matches = []
            wildcard_matches = []
            for record in self.override_records:
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
                return reply

        if self.zone_records:
            for rr in self.zone_records:
                if qtype in (QTYPE[rr.rtype], "ANY") and qname == normalize(str(rr.rname)):
                    reply.add_answer(rr)
                    reply.header.aa = 1
                    return reply

        for upstream in (self.settings["PrimaryUpstream"], self.settings["BackupUpstream"]):
            try:
                upstream_response = request.send(upstream, 53, tcp=False)
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
        self.doh_blocklist = []
        self.override_records = []
        self.settings = {
            "UseTCP": self.config.getboolean("DNS", "use_tcp"),
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
        

    def _search_override_records(self, query, record_type="any", search_param="id"):
        """ Search override records
        """
        for item in self.override_records:
            if item["rtype"] == record_type or record_type == "any":
                if search_param == "id":
                    if item["id"] == query:
                        return item

    def _Start(self):
        """ Start the process
        """
        if self.state == "running":
            raise exceptions.StateChangeError(f"DNS server is already running")
        try:
            self.state = "starting"
            resolver = DNSResolver(
                self.settings,
                self.doh_blocklist,
                self.override_records,
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

    def _UpdateDoHBlocklist(self, doh_blocklist):
        """ Update the DoH host blocklist
        """
        try:
            updated = []
            for host in doh_blocklist:
                if host in updated:
                    continue
                updated.append(host)
            self.doh_blocklist.clear()
            self.doh_blocklist.extend(updated)
        except Exception as err_msg:
            raise err_msg
        return None

    def _AddDNSOverride(self, scope, qtype, qname, rtype, rdata):
        """ Add a new DNS override record
        """
        try:
            id_ = len(self.override_records) + 1
            while self._search_override_records(id_, record_type="any", search_param="id") is not None:
                id_ += 1
            r = {
                "id": id_,
                "scope": scope,
                "qtype": qtype,
                "qname": qname,
                "rtype": rtype,
                "rdata": rdata,
            }
            rr = dict_to_rr(r)
            r["rr"] = rr
            self.override_records.append(r)
        except Exception as err_msg:
            raise err_msg
        return id_

    def _RemoveDNSOverride(self, id_):
        """ Remove an existing DNS override record
        """
        if not self._search_override_records(id_, record_type="any", search_param="id"):
            raise exceptions.OverrideRecordError(f"No override record with ID {id_} exists")
        try:
            r = self._search_override_records(id_, record_type="any", search_param="id")
            self.override_records.remove(r)
        except Exception as err_msg:
            raise err_msg
        return None
