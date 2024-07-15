# Overview

Find and configure [Prologix GPIB-ETHERNET controllers](https://prologix.biz/product/gpib-ethernet-controller/) on Linux, BSD, and MacOSX via command line. (Windows support shouldn't be too difficult to add, but it is not implemented yet.)

_**This is NOT OFFICIAL Prologix SOFTWARE. Code is not written by, maintained by, or warranted by Prologix, the company that manufactures the Prologix controller.**_

Installing this package adds command-line script `prologix-netfinder` for doing so.

Additionally, the commad-line script `prologix-getifaddrs` is insalled as a utility for retrieving network interface information on the host from which it is run (similar to `ifconfig`).

# Usage

Find all Prologix GPIB-ETHERNET controllers on the local network (make sure any intervening routers are not blocking port 3040, the port used by the Prologix NetFinder protocol).

```bash
$ prologix-netfinder list
```

```
INFO:prologix_netfinder.nfutil:Searching for Prologix ETHERNET-GPIB controllers via host interface enp3s0 (IP addr=192.168.0.14)
INFO:prologix_netfinder.nfutil:Searching for Prologix ETHERNET-GPIB controllers via host interface enp4s0 (IP addr=10.9.205.181)
INFO:nfcli:Found 1 Prologix GPIB-ETHERNET controller.

MAC address: 00:21:69:02:ab:43
IP address assignment: STATIC
IP address: 192.168.0.161   Netmask: 255.255.255.0   Gateway: 0.0.0.0
Hardware version: 1.3.0.0   Bootloader version: 1.3.0.0   Application version: 1.6.6.0
Uptime: 40 days 21:55:24
Bootloader or application mode: APPLICATION
Alert pending? OK
```

Change the IP address of the controller (identified by its MAC address, `00:21:69:02:ab:43`) to 192.168.0.162; set netmask to 255.255.255.0 and gateway to 0.0.0.0.

```bash
$ prologix-netfinder set-static -m 00:21:69:02:ab:43 -a 192.168.0.162 -n 255.255.255.0 -g 0.0.0.0 
```

```
INFO:prologix_netfinder.nfutil:Searching for Prologix ETHERNET-GPIB controllers via host interface enp3s0 (IP addr=192.168.0.14)
INFO:prologix_netfinder.nfutil:Searching for Prologix ETHERNET-GPIB controllers via host interface enp4s0 (IP addr=10.9.205.181)
INFO:nfcli:Updating network settings of Prologix GPIB-ETHERNET controller 00:21:69:01:4c:b9
INFO:nfcli:Network settings updated successfully.
```

Set the IP address of the same controller to be dynamically allocated by a router (DHCP). 

```bash
$ prologix-netfinder set-dynamic -m 00:21:69:02:ab:43
```

```
INFO:prologix_netfinder.nfutil:Searching for Prologix ETHERNET-GPIB controllers via host interface enp3s0 (IP addr=192.168.0.14)
INFO:prologix_netfinder.nfutil:Searching for Prologix ETHERNET-GPIB controllers via host interface enp4s0 (IP addr=10.9.205.181)
INFO:nfcli:Updating network settings of Prologix GPIB-ETHERNET controller 00:21:69:01:4c:b9
INFO:nfcli:Network settings updated successfully.
```

# Installation

## Install purely as a user of prologix-netfinder

```bash
pip install prologix-netfinder
```

## Install as a developer & user of prologix-netfinder

Change to a directory into which the `prologix_netfinder` sub-directory will be created. Then run the following to clone the repository & install an _editable_ version of the code (Python will symbolically link its installed files to the source code folder, such that changes to the source will be reflected in the installed package transparently):

```bash
git clone git@github.com:jllanfranchi/prologix_netfinder.git
pip install --editable prologix_netfinder
```

# Credits

The code in `prologix_netfinder/nfutil.py` and `prologix_netfinder/nfcli.py` is modified from the original Python 2 code by Prologix, which can be downloaded at [https://prologix.biz/downloads/nfcli.tar.gz](https://prologix.biz/downloads/nfcli.tar.gz). Again, Prologix has no association with the code contained in this repository. Though similar, this is a re-interpretation of their code.

Code in `prologix_netfinder/getifaddrs.py` is modified from the original code at [https://github.com/Gautier/minifail/blob/master/minifail/getifaddrs.py](https://github.com/Gautier/minifail/blob/master/minifail/getifaddrs.py) written by Gautier Hayoun.
