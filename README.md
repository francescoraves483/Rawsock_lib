# Rawsock_lib
Rawsock_lib version 0.1 - Jan 2 2018

Supported protocols: IPv4 and UDP

Licensed under GPLv2 - contains IP checksum calculation functions taken from Linux kernel version 4.19.1 (ipcsum_alth.h/.c).

Two example programs for broadcast communications (Example_send.c and Example_receive.c) are included, showing a possible use of the library. All the functions inside rawsock.c are documented through multi-line comments; a more extended documentation is actually work in progress, together with improving and adding new functions to the existing code.

A function (wlanLookup()) to automatically look for available wireless interfaces is included too.

This library is for Linux only, at the moment! Tested with Linux kernel 4.14.63.


**Library current contents:**
* Some useful constants, such as additional Ethertypes
* Some useful macros, for instance to compute the size of a standard IP/UDP packets (with no options in the IP header)
* Additional types, including "macaddr_t", to contain mac addresses as 1 B arrays with 6 places, "byte_t", to define in a more friendly manner byte arrays and variables (which are actually unsigned char) and “ethertype_t”, as a new, more friendly, name for unsigned short, to be used to specify a certain Ethertype
* General utility functions, including "wlanLookup()", which can be used to automatically look for a wireless interface on the device, two functions to print a given packet with a certain length (both in hexadecimal mode - "display_packet()" and in character mode - "display_packetc()") and functions to manage MAC address arrays ("macaddr_t" type)
* Functions to populate an Ethernet header (with source MAC, destination MAC and Ethertype) and to encapsulate an SDU inside an Ethernet packet, combining header and data coming from higher layers
* Functions to populate and manage IPv4 headers and packets
* Functions to populate and manage UDP headers and packets
* Test functions to inject a checksum error into UDP and IPv4 headers
* Two functions which can be useful when receiving UDP datagrams through a raw socket: "UDPgetpayloadsize()", allowing to get the payload size of a specified UDP datagram (given its pointer), and "UDPgetpacketpointers()", to obtain, given a certain buffer containing an UDP packet, the pointers to the header and payload sections

**Repository description:**

Raw sockets under Linux... made easier! C library for using raw sockets to send packets, supporting Linux. Version 0.1, supporting IPv4 and UDP, but ready for the addition of new protocols, such as WSMP. 

**Changelog:**

v0.1 - Very first public release

**Cross-compiling for OpenWrt, on PC Engines APU1D boards:**

If you are using this library to create programs to be cross-compiled and included on embedded boards, running OpenWrt, you can refer to the following instructions as a base for a correct cross-compilation.
These commands are actually related to PC Engines APU1D boards, which are x86_64 targets. They may differ if you are trying to compile for other boards.
The OpenWrt toolchain must be correctly set up on your PC, too.
```
x86_64-openwrt-linux-musl-gcc -I ./Rawsock_lib/ -o Example_send -static Example_send.c Rawsock_lib/rawsock.h Rawsock_lib/rawsock.c Rawsock_lib/ipcsum_alth.h Rawsock_lib/ipcsum_alth.c
x86_64-openwrt-linux-musl-gcc -I ./Rawsock_lib/ -o Example_receive -static Example_receive.c Rawsock_lib/rawsock.h Rawsock_lib/rawsock.c Rawsock_lib/ipcsum_alth.h Rawsock_lib/ipcsum_alth.c
```
Replacing "x86_64-openwrt-linux-musl-gcc" with the proper "gcc" binary.