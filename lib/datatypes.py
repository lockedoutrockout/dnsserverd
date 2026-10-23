"""
lib/datatypes.py

Custom datatype definitions
"""

import os
import sys
import subprocess
from . import exceptions

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
            "PrimaryUpstream": self.config["EXPLOITATION"]["dns_redirect_target_ip"],
            "RedirectDNSTraffic": self.config.getboolean("EXPLOITATION", "redirect_dns_traffic"),
            "BlockQUIC": self.config.getboolean("EXPLOITATION", "block_quic"),
            "BlockDoH": self.config.getboolean("EXPLOITATION", "block_doh")
        }
        self._settings = {
            "UseTCP": self.config.getboolean("DNS", "use_tcp"),
            "PrimaryUpstream": self.config["DNS"]["primary_upstream"],
            "BackupUpstream": self.config["DNS"]["backup_upstream"],
            "PrimaryUpstream": self.config["EXPLOITATION"]["dns_redirect_target_ip"],
            "RedirectDNSTraffic": self.config.getboolean("EXPLOITATION", "redirect_dns_traffic"),
            "BlockQUIC": self.config.getboolean("EXPLOITATION", "block_quic"),
            "BlockDoH": self.config.getboolean("EXPLOITATION", "block_doh")
        }

    def _Start(self):
        """ Start the process
        """
        def _template_subsystem_runner(logger, config):
            """ Runner thread for template subsystem
            """
            logger.info(f"Started template subsystem runner thread")
            sublogger = logging.getLogger("template_subsystem_runner")
            slch = logging.StreamHandler()
            log_level = int(config["LOGGING"]["log_level"])
            if log_level == -1:
                log_level = logging.DEBUG
            elif log_level == 0:
                log_level = logging.INFO
            elif log_level == 1:
                log_level = logging.ERROR
            slch.setLevel(log_level)
            slch.setFormatter(logging.Formatter("%(name)s - %(message)s"))
            sublogger.addHandler(slch)
            sublogger.info(f"Sublogger initialized for template subsystem subprocess")
            p = subprocess.Popen(
                [
                    "some",
                    "command",
                    "here..."
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )
            self.processes["template_subsystem"] = p
            for line in p.stdout:
                sublogger.info(line.rstrip())
            retcode = p.wait()
            if retcode != 0:
                logger.error(f"The template subsystem subprocess has exited with a non-zero return code of: {retcode}")
            else:
                logger.info(f"The template subsystem subprocess has exited")
            return None
            
        if self.state == "running":
            raise exceptions.StateChangeError(f"Template is already running")
        try:
            self.state = "starting"
            threading.Thread(target=_template_subsystem_runner, args=(self.logger, self.config), daemon=True).start()
            time.sleep(0.5)
            if self.processes["template_subsystem"].returncode:
                raise exceptions.ChildProcessExitedError(f"template subsystem exited with return code of: {self.processes['template_subsystem'].returncode}")
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
            for process_name in self.processes.keys():
                self.logger.debug(f"Stopping subprocess: {process_name}")
                process = self.processes[process_name]
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
                self.processes[process_name] = None
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
            self.stop()
            self.start()
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
            self.doh_blocklist = updated
        except Exception as err_msg:
            raise err_msg
        return None

    def _AddDNSOverride(self, scope, qtype, qname, rtype, rdata):
        """ Add a new DNS override record
        """
        pass

    def _RemoveDNSOverride(self, id_):
        """ Remove an existing DNS override record
        """
        pass
