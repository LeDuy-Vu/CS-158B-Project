# SJSU CS 158B Spring 2021
# Prof. Ben Reed
# Assignment 2
# Author: Le Duy Vu

import socket
import threading
import select
import serializeme

# CONSTANTS
HOST = '127.0.0.1'      # loopback interface aka localhost address
PORT = 1080             # SOCKS5 conventional port
BUFSIZE = 1024          # buffer size of socket.recv()
RELAY_BUFSIZE = 4096    # buffer size for relaying messages between remote server and client
USERNAME = "cs158b"     # username of client
PASSWORD = "Pa55word"   # password of client


# main function to start the SOCKS5 server on local host
def run():
    """
        This program acts as a simple local SOCKS5 server (referenced from RFC 1928).
        It only handles clients' TCP CONNECT requests and only works with IPv4 addresses and hostnames.
        The only authentication method implemented is username/password. The credentials are hardcoded in this file.
    """

    # set up socket
    soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)     # TCP connection
    soc.bind((HOST, PORT))                                      # bind to proper HOST and port
    soc.listen()                                                # server start listening

    while True:     # waiting for connection and start a new thread for each connection
        try:
            conn, addr_port = soc.accept()
        except (KeyboardInterrupt, InterruptedError):   # shut down server by exit (Ctrl C) command in terminal
            soc.close()
            print("SOCKS5 server shut down")
            break

        thread = threading.Thread(target=start_thread, args=(conn,))
        thread.daemon = True
        thread.start()


# main function each thread runs after being created
def start_thread(conn):
    if check_method_selection(conn):    # if method selection is approved
        reply_method_selection(conn, True)

        if check_authentication(conn):  # if negotiation succeeds
            reply_authentication(conn, True)

            rep, remote_conn, bound_addr_port = check_connect_request(conn)
            reply_connect_request(conn, rep, bound_addr_port)
            if rep == 0:                # if connect request is valid
                enter_relay_phase(remote_conn, conn)
        else:
            reply_authentication(conn, False)
    else:
        reply_method_selection(conn, False)

    # end service thread, close sockets
    remote_conn.close()
    conn.close()


# checks client's "version identifier/method selection message"
# return True if the request is valid, False otherwise
def check_method_selection(conn):
    # retrieve and breakdown the request
    data = conn.recv(BUFSIZE)
    request_format = {"VER"     : "1B",
                      "NMETHODS": ("1B", "", "METHODS"),
                      "METHODS" : {"METHOD": "1B"}}
    packet = serializeme.Deserialize(data, request_format)

    # process request content
    if packet.get_value("VER") != 5:            # check if SOCKS version 5
        return False
    nmethods = packet.get_value("NMETHODS")     # number of authentication methods offered
    if nmethods == 0:                           # check if any authentication method is offered
        return False
    for i in range(1, nmethods + 1):            # check if username/password method is offered
        if data[-i] == 2:   # I can't use serializeme in this line because the API offers no way to check value of a variable-length field
            return True
    return False


# replies to client's request
def reply_method_selection(conn, flag):
    # True flag: select method 02 for username/password authentication
    # False flag: select method FF = 255 for no acceptable method
    selection_format = {"VER"   : ("1B", 5),
                        "METHOD": ("1B", 2 if flag else 255)}
    conn.sendall(serializeme.Serialize(selection_format).packetize())


# checks client's sub-negotiation message (RFC 1929)
# return True if the credentials are valid, False otherwise
def check_authentication(conn):
    # retrieve and breakdown the negotiation
    data = conn.recv(BUFSIZE)
    negotiation_format = {"VER"     : "1B",
                          "UNAME"   : serializeme.PREFIX_LENGTH,
                          "PASSWD"  : serializeme.PREFIX_LENGTH}
    packet = serializeme.Deserialize(data, negotiation_format)

    # process negotiation content
    if packet.get_value("VER") != 1:            # check if the sub-negotiation version is 1 for username/password
        return False
    if packet.get_value("UNAME") != USERNAME:   # check credentials
        return False
    if packet.get_value("PASSWD") != PASSWORD:  # check credentials
        return False
    return True


# replies to client's sub-negotiation message
def reply_authentication(conn, flag):
    # True flag: authentication success, STATUS = 0
    # False flag: authentication fail, STATUS != 0
    response_format = {"VER"    : ("1B", 1),
                       "STATUS" : ("1B", 0 if flag else 1)}
    conn.sendall(serializeme.Serialize(response_format).packetize())


# checks client's connect request
# return a tuple of 3 including reply code, remote connection, and bound address respectively
def check_connect_request(conn):
    # retrieve and breakdown the request
    data = conn.recv(BUFSIZE)
    first_part = {"VER" : "1B",     # the first portion of the request (first 4 bytes)
                  "CMD" : "1B",
                  "RSV" : "1B",
                  "ATYP": "1B"}
    first_portion = serializeme.Deserialize(data[0:4], first_part)

    rep = 0                             # reply code for reply message, default = 0 aka success. check RFC 1928 section 6 for a complete list with meanings
    remote_conn = 0                     # placeholder for TCP connection to remote host
    bound_addr_port = ('0.0.0.0', 0)    # placeholder for SOCKS5 server's bound addr

    # process request content
    if first_portion.get_value("VER") != 5:
        rep = 7
    if first_portion.get_value("CMD") != 1:     # only CMD = 1 aka CONNECT request is supported
        rep = 7
    if first_portion.get_value("RSV") != 0:
        rep = 7

    if first_portion.get_value("ATYP") == 1:    # ATYP = 1 aka receiving IPv4 addr
        second_part = {"DST.ADDR": ("4B", serializeme.IPv4),
                       "DST.PORT": "2B"}
        second_portion = serializeme.Deserialize(data[4:], second_part)
        remote_conn, bound_addr_port = connect_to_remote_host(second_portion.get_value("DST.ADDR"), second_portion.get_value("DST.PORT"))
    elif first_portion.get_value("ATYP") == 3:  # ATYP = 3 aka receiving domain name
        second_part = {"DST.ADDR": serializeme.PREFIX_LENGTH,
                       "DST.PORT": "2B"}
        second_portion = serializeme.Deserialize(data[4:], second_part)

        try:    # try to resolve host name into IPv4 addr. if failure, change reply code
            addr = socket.gethostbyname(second_portion.get_value("DST.ADDR"))
            remote_conn, bound_addr_port = connect_to_remote_host(addr, second_portion.get_value("DST.PORT"))
        except socket.gaierror:
            rep = 4
    else:                                       # ATYP = any other value: not supported
        rep = 8

    return rep, remote_conn, bound_addr_port


# makes a TCP connection to the request remote host
def connect_to_remote_host(addr, port):
    remote_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)     # TCP connection
    remote_conn.connect((addr, port))
    bound_addr_port = remote_conn.getsockname()                         # local SOCKS5 server's bound addr
    return remote_conn, bound_addr_port


# replies to client's connection request
def reply_connect_request(conn, rep, bound_addr_port):
    reply_format = {"VER"       : ("1B", 5),
                    "REP"       : ("1B", rep),                  # reply code
                    "RSV"       : "1B",
                    "ATYP"      : ("1B", 1),
                    "BND.ADDR"  : ("ipv4", bound_addr_port[0]), # if connect to remote host success, fill in SOCKS5 server bound addr. otherwise, fill 0
                    "BND.PORT"  : ("2B", bound_addr_port[1])}   # if connect to remote host success, fill in SOCKS5 server bound port. otherwise, fill 0
    conn.sendall(serializeme.Serialize(reply_format).packetize())


# becomes the middle man between the client and the remote server
# source: https://rushter.com/blog/python-socks-server/
def enter_relay_phase(remote_conn, local_conn):
    while True:
        # local and remote socket wait until ready for reading
        r, w, e = select.select([local_conn, remote_conn], [], [])

        if local_conn in r:     # when local socket receives something
            data = local_conn.recv(RELAY_BUFSIZE)
            if remote_conn.send(data) <= 0:
                break

        if remote_conn in r:    # when remote socket receives something
            data = remote_conn.recv(RELAY_BUFSIZE)
            if local_conn.send(data) <= 0:
                break


if __name__ == '__main__':
    run()
