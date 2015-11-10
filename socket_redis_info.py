#!/usr/bin/env python2
"""
Modified from http://kmkeen.com/socketserver/
"""

import socket
def client(string):
    HOST, PORT = '172.24.16.68', 6386
    # SOCK_STREAM == a TCP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #sock.setblocking(0)  # optional non-blocking
    sock.connect((HOST, PORT))
    sock.send(string)
    print "tx"
    reply = sock.recv(16384)  # limit reply to 16K
    print "rx"
    sock.close()
    print "close"
    return reply

#assert client('2+2') == '4'
i = client("INFO")
print "%r" % i