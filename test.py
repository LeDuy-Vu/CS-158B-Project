import serializeme
import socket

if __name__ == '__main__':
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((socket.gethostbyname('www.google.com'), 80))
    bind_addr_port = s.getsockname()
    s.close()

    print(bind_addr_port[0])
    print(bind_addr_port[1])

    reply_format = {"VER": ("1B", 5),
                    "REP": ("1B", 0),
                    "RSV": "1B",
                    "ATYP": ("1B", 1),
                    "BND.ADDR": ("ipv4", bind_addr_port[0]),
                    "BND.PORT": ("2B", bind_addr_port[1])}
    print(serializeme.Serialize(reply_format).packetize())
