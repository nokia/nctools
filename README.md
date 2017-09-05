# nctools - Python tools for NETCONF
"nctools" is a collection of NETCONF tools in Python using the paramiko SSHv2 library.

## ncproxy - NETCONF Proxy
The tool "ncproxy" is a transparent NETCONF proxy. It is deployed between the NETCONF
server and NETCONF client to provide logging capabilities. From the NETCONF server
point of view ncproxy acts as client and from the NETCONF client point of view it
acts as server. All hello messages, RPC requests, RPC responses and notification
messages are subject of logging.

In the current version, only NETCONF over SSHv2 using password authentication
is supported. Both framing methods end-of-message-framing (base1:0) and chunked
framing (base1:1) are supported. Username and password are provided by the NETCONF
client. Ncproxy is reusing this information to get connectivity towards to server.

The ncproxy tool is helpful for network integrators, who want to troubleshoot NETCONF
without having logging capabilities for neither the server nor the client. Capturing
the SSHv2 traffic using tools like tcpdump, snoop or wireshark does typically not help,
as there is no easy way to break SSHv2 privacy.

For improved trouble-shooting, ncproxy can be used to modify server and client messages
as they are forwarded through the proxy. A JSON file is used to define the set of
modification rules to be used. Each modification rule contains a match criteria (regex)
and patch action.

Beside of patching messages ncproxy support auto-responses. The user can define
a match criteria, in which case the ncproxy is answer the clients NETCONF request on
behalf of the NETCONF server. In conclusion, those rpc-requests are never send to the
server, which allows to test NETCONF features, which are not yet implemented by the
server.

Example patch01.json removes some server and client capabilities during <hello>
message exchange:

```javascript
{
  "server-msg-modifier": [
    {
      "match": "<capability>urn:ietf:params:netconf:capability:writable-running:1.0</capability>",
      "patch": "<!-- writable-running removed -->"
    },
    {
      "match": "<capability>urn:ietf:params:netconf:base:1.1</capability>",
      "patch": "<!-- base:1.1 removed -->"
    }    
  ],
  "client-msg-modifier": [
    {
      "match": "<capability>urn:ietf:params:netconf:base:1.1</capability>",
      "patch": "<!-- base:1.1 removed -->"
    }
  ],
  "auto-respond": []
}
```

Example patch02.json is replaces rpc-error messages with rpc-reply/ok responses:
```javascript
{
  "server-msg-modifier": [
    {
      "match": "[\\s\\S]+(message-id=\"\\d+\")[\\s\\S]+<rpc-error>[\\s\\S]+",
      "patch": "<rpc-reply \\1 xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\"><ok/></rpc-reply>"     
    }
  ],
  "client-msg-modifier": [],
  "auto-respond": []
}
```

Example patch03.json automatically response with rpc-reply/ok for any copy-config requests.
```javascript
{
  "server-msg-modifier": [],
  "client-msg-modifier": [],
  "auto-respond": [
    {
      "match": "[\\s\\S]+(message-id=\"\\d+\")[\\s\\S]+<copy-config>[\\s\\S]+",
      "response": "<rpc-reply \\1 xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\"><ok/></rpc-reply>"
    }
  ]
}
```

Usage example, help:
```
$ ./ncproxy.py --help
usage: ncproxy.py [-h] [--version] [-v] [-d] [--logfile filename]
                  [--serverlog filename] [--clientlog filename]
                  [--patch filename] [--port tcpport]
                  netconf://<hostname>[:port]

optional arguments:
  -h, --help                   show this help message and exit
  --version                    show program's version number and exit

  -v, --verbose                enable logging
  -d, --debug                  enable ssh-lib logging
  --logfile filename           trace/debug log (default: <stderr>)
  --serverlog filename         server log (default: <stdout>)
  --clientlog filename         client log (default: <stdout>)

  --patch filename             Patch NETCONF messages (default: <none>)

  --port tcpport               TCP-port ncproxy is listening
  netconf://<hostname>[:port]  Netconf over SSH server
```

Usage example, with patching:
```
$ ./ncproxy.py --patch patch03.json -vvvvv 135.227.236.97:830
17/09/05 11:08:24,38  INFO     Listening for client connection ...
17/09/05 11:08:26,799 DEBUG    Server Key: f2b3c60ea34bf2cd5bd1e1d8c0203228
```