"""
lib/api.py

Contains the DBus interface
"""

import os
import sys
import logging
import configparser
from pydbus import SystemBus
from pydbus.generic import signal
from gi.repository import GLib
from . import (
    datatypes,
    exceptions
)

BUS_NAME = "com.dnsserverd.DNSServer"
OBJECT_PATH = "/com/dnsserverd/DNSServer"
INTERFACE_XML = """
<node>
    <interface name="com.dnsserverd.DNSServer">
        <!-- Methods -->
        <method name="Start"/>
        <method name="Stop"/>
        <method name="Restart"/>
        <method name="ApplyConfiguration"/>
        <method name="UpdateDoHBlocklist">
            <arg name="hosts" type="as" direction="in"/>
            <arg name="append" type="b" direction="in"/>
        </method>
        <method name="ImportZoneFile">
            <arg name="infile" type="s" direction="in"/>
            <arg name="category" type="s" direction="in"/>
            <arg name="scope" type="s" direction="in"/>
            <arg name="ids" type="ai" direction="out"/>
        </method>
        <method name="ExportZoneFile">
            <arg name="outfile" type="s" direction="in"/>
            <arg name="category" type="s" direction="in"/>
            <arg name="scope" type="s" direction="in"/>
        </method>
        <method name="AddDNSRecord">
            <arg name="category" type="s" direction="in"/>
            <arg name="scope" type="s" direction="in"/>
            <arg name="rtype" type="s" direction="in"/>
            <arg name="rname" type="s" direction="in"/>
            <arg name="rdata" type="s" direction="in"/>
            <arg name="ttl" type="i" direction="in"/>
            <arg name="id" type="i" direction="out"/>
        </method>
        <method name="RemoveDNSRecord">
            <arg name="id" type="i" direction="in"/>
        </method>
        

        <!-- Properties -->
        <!-- Read Only -->
        <property name="State" type="s" access="read"/>
        <property name="ZoneRecords" type="aa{sv}" access="read"/>
        <property name="OverrideRecords" type="aa{sv}" access="read"/>
        <property name="DoHBlocklist" type="as" access="read"/>
        <!-- Read/Write -->
        <property name="UseTCP" type="b" access="readwrite"/>
        <property name="PrimaryUpstream" type="s" access="readwrite"/>
        <property name="BackupUpstream" type="s" access="readwrite"/>
        <property name="DNSRedirectTargetIP" type="s" access="readwrite"/>
        <property name="RedirectDNSTraffic" type="b" access="readwrite"/>
        <property name="BlockQUIC" type="b" access="readwrite"/>
        <property name="BlockDoH" type="b" access="readwrite"/>

        <!-- Signals -->
        <signal name="StateChanged">
            <arg type="s" name="old_state"/>
            <arg type="s" name="new_state"/>
        </signal>
        <signal name="ConfigurationChanged">
            <arg type="s" name="setting"/>
            <arg type="s" name="old_value"/>
            <arg type="s" name="new_value"/>
        </signal>
        <signal name="ConfigurationApplied">
            <arg type="a{sv}" name="old_config"/>
            <arg type="a{sv}" name="new_config"/>
        </signal>
        <signal name="DoHBlocklistUpdated">
            <arg type="as" name="old_blocklist"/>
            <arg type="as" name="new_blocklist"/>
        </signal>
        <signal name="DNSRecordsUpdated">
            <arg type="s" name="action"/>
            <arg type="s" name="category"/>
            <arg type="a{sv}" name="record"/>
        </signal>
    </interface>
</node>
"""

def dict_to_dbus_asv(d):
    """ Sanatizes a dictionary for use as an array of string variants in DBus
    """
    for k in d.keys():
        s = str(d[k])
        d[k] = s
    return d

class DNSServerService(datatypes.DNSServer):
    """ DBus interface object
    """

    # Signals
    StateChanged = signal()
    ConfigurationChanged = signal()
    ConfigurationApplied = signal()
    DoHBlocklistUpdated = signal()
    DNSRecordsUpdated = signal()

    def __init__(self):
        self.version = "0.1"
        config = configparser.ConfigParser()
        config.read(sys.argv[1:])
        logger = logging.getLogger()
        super().__init__(config=config, logger=logger)

    # Methods
    def Start(self):
        """ Start endpoint
        """
        self.logger.info(f"DBus API got call to Start")
        try:
            _old = self.state
            self._Start()
            self.StateChanged(_old, self.state)
        except Exception as err_msg:
            self.logger.error(f"DBus API encountered an exception during call to Start: {err_msg}")
            raise exceptions.StateChangeError(f"An error has prevented the template from starting") from err_msg
        return None

    def Stop(self):
        """ Stop endpoint
        """
        self.logger.info(f"DBus API got call to Stop")
        try:
            _old = self.state
            self._Stop()
            self.StateChanged(_old, self.state)
        except Exception as err_msg:
            self.logger.error(f"DBus API encountered an exception during call to Stop: {err_msg}")
            raise exceptions.StateChangeError(f"An error has prevented the AP host from stopping") from err_msg
        return None

    def Restart(self):
        """ Restart endpoint
        """
        self.logger.info(f"DBus API got call to Restart")
        try:
            _old = self.state
            self._Restart()
            self.StateChanged(_old, self.state)
        except Exception as err_msg:
            self.logger.error(f"DBus API encountered an exception during call to Restart: {err_msg}")
            raise exceptions.StateChangeError(f"An error has prevented the AP host from restarting") from err_msg
        return None

    def ApplyConfiguration(self):
        """ Apply endpoint
        """
        self.logger.info(f"DBus API got call to Apply")
        try:
            _old = dict_to_dbus_asv(self.settings)
            self._ApplyConfiguration()
            self.ConfigurationApplied(_old, dict_to_dbus_asv(self.settings))
        except Exception as err_msg:
            self.logger.error(f"DBus API encountered an exception during call to Apply: {err_msg}")
        return None

    def UpdateDoHBlocklist(self, hosts, append):
        """ Update the DNS-over-HTTPS host blocklist
        """
        self.logger.info(f"DBus API got call to UpdateDoHBlocklist")
        try:
            _old = self.doh_blocklist.doh_blocklist
            self._UpdateDoHBlocklist(hosts, append)
            self.DoHBlocklistUpdated(_old, self.doh_blocklist.doh_blocklist)
        except Exception as err_msg:
            self.logger.error(f"DBus API encountered an exception during call to UpdateDoHBlocklist: {err_msg}")
            raise err_msg
        return None

    def ImportZoneFile(self, infile, category, scope):
        """ Import DNS records of the specified category from a zonefile
        """
        self.logger.info(f"DBus API got call to ImportZoneFile")
        try:
            ids = self.dns_records.import_zone_file(infile, category, scope)
        except Exception as err_msg:
            self.logger.error(f"DBus API encountered an exception during call to ImportZoneFile: {err_msg}")
            raise err_msg
        return ids
            

    def ExportZoneFile(self, outfile, category, scope):
        """ Export the records for a given category to a zonefile
        """
        self.logger.info(f"DBus API got call to ExportZoneFile")
        try:
            self.dns_records.export_zone_file(outfile, category, scope)
        except Exception as err_msg:
            self.logger.error(f"DBus API encountered an exception during call to ExportZoneFile: {err_msg}")
            raise err_msg
        return None

    def AddDNSRecord(self, category, scope, rtype, rname, rdata, ttl):
        """ Add a new DNS record
        """
        self.logger.info(f"DBus API got call to AddDNSRecord")
        try:
            record = self._AddDNSRecord(category, scope, rtype, rname, rdata, ttl)
            self.DNSRecordsUpdated("add", category, record)
        except Exception as err_msg:
            self.logger.error(f"DBus API encountered an exception during call to AddDNSRecord: {err_msg}")
            raise err_msg
        return record[0]

    def RemoveDNSRecord(self, id_):
        """ Remove an existing DNS record
        """
        self.logger.info(f"DBus API got call to RemoveDNSRecord")
        try:
            record = self._RemoveDNSRecord(id_)
            self.DNSRecordsUpdated("remove", record["category"], record)
        except Exception as err_msg:
            self.logger.error(f"DBus API encountered an exception during call to RemoveDNSRecord: {err_msg}")
            raise err_msg
        return None
        
    # Properties
    @property
    def State(self):
        return self.state

    @property
    def ZoneRecords(self):
        return self.dns_records["by_category"]["zone"]

    @property
    def OverrideRecords(self):
        return self.dns_records["by_category"]["override"]

    @property
    def DoHBlocklist(self):
        return self.doh_blocklist.doh_blocklist

    @property
    def UseTCP(self):
        return self.settings["UseTCP"]
    @UseTCP.setter
    def UseTCP(self, value):
        self.logger.info(f"Readwrite property UseTCP set to {value} from {self._settings["UseTCP"]}")
        _old = self._settings["UseTCP"]
        try:
            self._settings["UseTCP"] = value
            self.ConfigurationChanged("UseTCP", _old, self._settings["UseTCP"])
        except Exception as err_msg:
            self.logger.error(f"DBus API encountered an exception while setting value of readwrite property UseTCP from: {_old} to: {value}")
            raise exceptions.ConfigurationError(f"Failed to update value of read/write property: UseTCP")

    @property
    def PrimaryUpstream(self):
        return self.settings["PrimaryUpstream"]
    @PrimaryUpstream.setter
    def PrimaryUpstream(self, value):
        self.logger.info(f"Readwrite property PrimaryUpstream set to {value} from {self._settings["PrimaryUpstream"]}")
        _old = self._settings["PrimaryUpstream"]
        try:
            self._settings["PrimaryUpstream"] = value
            self.ConfigurationChanged("PrimaryUpstream", _old, self._settings["PrimaryUpstream"])
        except Exception as err_msg:
            self.logger.error(f"DBus API encountered an exception while setting value of readwrite property PrimaryUpstream from: {_old} to: {value}")
            raise exceptions.ConfigurationError(f"Failed to update value of read/write property: PrimaryUpstream")

    @property
    def BackupUpstream(self):
        return self.settings["BackupUpstream"]
    @BackupUpstream.setter
    def BackupUpstream(self, value):
        self.logger.info(f"Readwrite property BackupUpstream set to {value} from {self._settings["BackupUpstream"]}")
        _old = self._settings["BackupUpstream"]
        try:
            self._settings["BackupUpstream"] = value
            self.ConfigurationChanged("BackupUpstream", _old, self._settings["BackupUpstream"])
        except Exception as err_msg:
            self.logger.error(f"DBus API encountered an exception while setting value of readwrite property BackupUpstream from: {_old} to: {value}")
            raise exceptions.ConfigurationError(f"Failed to update value of read/write property: BackupUpstream")

    @property
    def DNSRedirectTargetIP(self):
        return self.settings["DNSRedirectTargetIP"]
    @DNSRedirectTargetIP.setter
    def DNSRedirectTargetIP(self, value):
        self.logger.info(f"Readwrite property DNSRedirectTargetIP set to {value} from {self._settings["DNSRedirectTargetIP"]}")
        _old = self._settings["DNSRedirectTargetIP"]
        try:
            self._settings["DNSRedirectTargetIP"] = value
            self.ConfigurationChanged("DNSRedirectTargetIP", _old, self._settings["DNSRedirectTargetIP"])
        except Exception as err_msg:
            self.logger.error(f"DBus API encountered an exception while setting value of readwrite property DNSRedirectTargetIP from: {_old} to: {value}")
            raise exceptions.ConfigurationError(f"Failed to update value of read/write property: DNSRedirectTargetIP")

    @property
    def RedirectDNSTraffic(self):
        return self.settings["RedirectDNSTraffic"]
    @RedirectDNSTraffic.setter
    def RedirectDNSTraffic(self, value):
        self.logger.info(f"Readwrite property RedirectDNSTraffic set to {value} from {self._settings["RedirectDNSTraffic"]}")
        _old = self._settings["RedirectDNSTraffic"]
        try:
            self._settings["RedirectDNSTraffic"] = value
            self.ConfigurationChanged("RedirectDNSTraffic", _old, self._settings["RedirectDNSTraffic"])
        except Exception as err_msg:
            self.logger.error(f"DBus API encountered an exception while setting value of readwrite property RedirectDNSTraffic from: {_old} to: {value}")
            raise exceptions.ConfigurationError(f"Failed to update value of read/write property: RedirectDNSTraffic")

    @property
    def BlockQUIC(self):
        return self.settings["BlockQUIC"]
    @BlockQUIC.setter
    def BlockQUIC(self, value):
        self.logger.info(f"Readwrite property BlockQUIC set to {value} from {self._settings["BlockQUIC"]}")
        _old = self._settings["BlockQUIC"]
        try:
            self._settings["BlockQUIC"] = value
            self.ConfigurationChanged("BlockQUIC", _old, self._settings["BlockQUIC"])
        except Exception as err_msg:
            self.logger.error(f"DBus API encountered an exception while setting value of readwrite property BlockQUIC from: {_old} to: {value}")
            raise exceptions.ConfigurationError(f"Failed to update value of read/write property: BlockQUIC")

    @property
    def BlockDoH(self):
        return self.settings["BlockDoH"]
    @BlockDoH.setter
    def BlockDoH(self, value):
        self.logger.info(f"Readwrite property BlockDoH set to {value} from {self._settings["BlockDoH"]}")
        _old = self._settings["BlockDoH"]
        try:
            self._settings["BlockDoH"] = value
            self.ConfigurationChanged("BlockDoH", _old, self._settings["BlockDoH"])
        except Exception as err_msg:
            self.logger.error(f"DBus API encountered an exception while setting value of readwrite property BlockDoH from: {_old} to: {value}")
            raise exceptions.ConfigurationError(f"Failed to update value of read/write property: BlockDoH")

    

    

def init_dbus_api(name=BUS_NAME, path=OBJECT_PATH, xml=INTERFACE_XML, logger=None):
    """ Launch the DBus interface
    """
    if logger:
        logger.info(f"Bringing up DBus API. Interface: {name} Path: {path}")
    bus = SystemBus()
    bus.publish(name, (path, TemplateService(), xml))
    GLib.MainLoop().run()
    return None
