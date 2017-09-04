# nctools - Python tools for NETCONF
"nctools" is a collection of NETCONF tools in Python using the paramiko SSHv2 library.

## ncproxy - NETCONF Proxy
The tool "ncproxy" is a transparent NETCONF proxy. It is deployed between the NETCONF
server and NETCONF client to provide logging capabilities. From the NETCONF server
point of view ncproxy acts as client and from the NETCONF client point of view it
acts as server. All hello messages, RPC requests, RPC responses and notification
messages are subject of logging.

The ncproxy tool is helpful for network integrators, who want to troubleshoot NETCONF
without having logging capabilities for neither the server nor the client. Capturing
the SSHv2 traffic using tools like tcpdump, snoop or wireshark does typically not help,
as there is no easy way to break SSHv2 privacy.
 
