#!/usr/bin/env python3

"""
dnsserverd.py

DNS server component daemon
"""

import os
import sys
import logging
import configparser
from lib import api

def main(config, logger):
    """ Main function. Controls program execution
    """
    logger.info(f"Starting the DNS server daemon")
    try:
        api.init_dbus_api()
    except KeyboardInterrupt:
        logger.info(f"Keyboard interupt recieved, stopping DNS service now")
        return None

# Begin execution
if __name__ == "__main__":
    # Read the configuration file
    config = configparser.ConfigParser()
    config.read(sys.argv[1])

    # Set up the logger
    log_level = int(config["LOGGING"]["log_level"])
    if log_level == -1:
        log_level = logging.DEBUG
    elif log_level == 0:
        log_level = logging.INFO
    elif log_level == 1:
        log_level = logging.ERROR
    else:
        raise Exception(f"Invalid log level specified in configuration file")
    if bool(config["LOGGING"]["log_file"]):
        log_file = config["LOGGING"]["log_file"]
        if "~" in log_file:
            log_file = os.path.expanduser(log_file)
        if not os.path.isdir(os.path.split(log_file)[0]):
            os.makedirs(os.path.split(log_file)[0])
        logging.basicConfig(
            level=logging.DEBUG,
            format="%(asctime)s - %(levelname)s - %(message)s",
            filename=log_file
        )
    else:
        logging.basicConfig(
            level=logging.DEBUG,
            format="%(asctime)s - %(levelname)s - %(message)s",
        )
    logger = logging.getLogger()

    # Enter the main function
    main(config, logger)




