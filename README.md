# simplewebsocat
A TCP server forwarding connections to (secure) websockets - VERSION 20240127Z1245SB by S. Bärwolf

Simplewebsocat is a very simplistic tool to make websockets accessable via normal sockets.
Usually this enables traditional tools connecting services hidden behind websockets.
It therefore creates a new listening socket on the local machine and bit-bangs data from incoming connections to the websocket.
By default simplewebsocat can handle 16 concurrent connections (Use "-DMYMAXCONNECTIONS=<...>" to modify this at build time).


In contrast to the following tools, it's a pure C implementation (using libcurl) - without any cloud access/downloads involved.

* https://github.com/vi/websocat          (RUST)
* https://github.com/erebe/wstunnel       (RUST)
* https://github.com/websockets/wscat     (JS)
* https://github.com/joewalnes/websocketd (GO)
* https://github.com/alexanderGugel/wsd   (GO)



Usage:
         -h/--help                                               this help

         -u/--url <wss://user:password@domain:port/websocket>    the websocket-url to relay to
         --proxy <http://user:password@domain:port/>             the address for an proxy server to establish connections to websocket, not using "--proxy" means direct connection
         --capath </etc/ssl/certs/>                              path to directory filled with files of trusted certificate authorities
         --unsecure                                              do not check security/certificates - force connection

         -a/--bindaddress <localhost|127.0.0.1|0.0.0.0>          the IP address the service listens to for incoming connections
         -p/--bindport <41024>                                   the TCP portnumber the service listens to for incoming connections

         -k/--keepalive <45>                                     the number of seconds of tolerated inactivity before sending ping (0 means deactivate)
         -t/--timeout   <15>                                     the maximum number of seconds waiting before polling the connectionstate (should be smaller then keepalive)
         -v/--verbose                                            put libcurl in verbose mode an output more debug information
         -d/--dumpconfig                                         after start print current settings to stderr


Calling example:
simplewebsocat --dumpconfig --url wss://user:password@demo.matrixstorm.com/localhost:22 --timeout 17 --keepalive 30 --bindport 41022


by S. Bärwolf, Rudolstadt 2024
