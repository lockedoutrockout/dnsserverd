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

BUS_NAME = "com.templated.Template"
OBJECT_PATH = "/com/templated/Template"
INTERFACE_XML = """
<node>
    <interface name="com.templated.Template">
        <!-- Methods -->
        <method name="Start"/>
        <method name="Stop"/>
        <method name="Restart"/>
        <method name="ApplyConfiguration"/>

        <!-- Properties -->
        <!-- Read Only -->
        <property name="State" type="s" access="read"/>
        <!-- Read/Write -->
        <property name="Foo" type="s" access="readwrite"/>

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

class TemplateService(datatypes.Template):
    """ DBus interface object
    """

    # Signals
    StateChanged = signal()
    ConfigurationChanged = signal()
    ConfigurationApplied = signal()

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

    # Properties
    @property
    def State(self):
        return self.state

    @property
    def Foo(self):
        return self.settings["Foo"]
    @Foo.setter
    def Foo(self, value):
        self.logger.info(f"Readwrite property Foo set to {value} from {self._settings["Foo"]}")
        _old = self._settings["Foo"]
        try:
            self._settings["Foo"] = value
            self.ConfigurationChanged("Foo", _old, self._settings["Foo"])
        except Exception as err_msg:
            self.logger.error(f"DBus API encountered an exception while setting value of readwrite property Foo from: {_old} to: {value}")
            raise exceptions.ConfigurationError(f"Failed to update value of read/write property: Foo")

def init_dbus_api(name=BUS_NAME, path=OBJECT_PATH, xml=INTERFACE_XML, logger=None):
    """ Launch the DBus interface
    """
    if logger:
        logger.info(f"Bringing up DBus API. Interface: {name} Path: {path}")
    bus = SystemBus()
    bus.publish(name, (path, TemplateService(), xml))
    GLib.MainLoop().run()
    return None
