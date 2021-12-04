import socket
import serializeme
from serializeme import Serialize, Deserialize

# Global variables
IP = "127.0.0.1"
PORT = 53

def doDNS(data):
    query = Deserialize(data, {
            "ID": ("2B"),
            "Flags": ("2B"),
            "QDcount":("2B"),
            "ANcount":("2B"),
            "NS count":("2B"),
            "ARcount":("2B"),
            "qname": (serializeme.NULL_TERMINATE, serializeme.HOST),
            "qtype": ("2B"),
            "qclass": ("2B")
            })
    hostname = query.get_field("qname").value
    type = query.get_field("qtype").value
    dns_domain, dns_servers = read_piman_yml()

    if type == 33 and 'metrics.boston.cs158b' == hostname:
        return resolve_srv_records(dns_domain, query)
    elif type == 12 and "2.16.172" in hostname:
        return ip_to_hostname(hostname, query)
    #hostname to IP resolution works
    elif type == 1 and 'boston.cs158b' in hostname:
        return hostname_to_ip(hostname, query)
    else:
        #forward it to google dns (works)
        sd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sd.connect((dns_servers[0], 53)) #DNS uses port 53
        sd.send(data)
        response = sd.recv(1024)
        return response

def resolve_srv_records(dns_domain, query):
    answers = bytearray()
    pis = get_pis()
    for port in pis:
        domain = f'pi{port}.{dns_domain}'

        answer = bytearray(b'\xc0\x0c')
        answer += Serialize({
            'Type': ('2B', 33),
            'class': ('2B', 1),
            'TTL': ('4B', 300)
        }).packetize()

        target = bytearray()
        for part in domain.split('.'):
            target += bytearray([len(part)])
            target += str.encode(part)
        target += bytearray(b'\x00')

        data_length = 2 + 2 + 2 + len(target)
        answer += Serialize({
            'Data length': ('2B', data_length),
            'Priority': ('2B', 1),
            'Weight': ('2B', 1),
            'Port': ('2B', 9100)
        }).packetize()
        answer += target
        answers += answer

    q_name = query.get_field('qname').value
    q_type = query.get_field('qtype').value
    q_class = query.get_field('qclass').value

    qpart = bytearray()
    for part in q_name.split('.'):
        qpart += bytearray([len(part)])
        qpart += str.encode(part)
    qpart += b'\x00'

    rest = Serialize({
        'Type': ('2B', int(q_type)),
        'class': ('2B', int(q_class))
    }).packetize()

    qpart += rest

    num_answers = len(pis)
    header = Serialize({
        'ID': ('2B', query.get_field('ID').value),
        'Response': (1, 1),
        'Opcode': 4,
        'Authoritative': 1,
        'Truncated': 1,
        'RD': (1, 1),
        'RA': (1, 1),
        'Z': 1,
        'Answer authenticated': 1,
        'non-auth data': 1,
        'Reply code': 4,
        'Questions': ('2B', 1),
        'Answer RRs': ('2B', num_answers),
        'Authority RRs': '2B',
        'Additional RRs': '2B'
    }).packetize()
    res = header + qpart + answers
    return res

def get_pis():
    with open('./hosts.csv') as rf:
        lines = rf.readlines()
        pis = [line.split(';')[1].split('.')[-1] for line in lines]
        return pis

def hostname_to_ip(hostname, query):
    parts = hostname.split('.')
    pipart = parts[0]
    pinum = pipart[2:]
    firstpart = Serialize({
            'ID': ('2B', query.get_field('ID').value),
            'pflags': ('2B', 33152),
            'qcnt': ('2B', 1),
            'acnt': ('2B', 1),
            'ncnt': ('2B', 0),
            'mcnt': ('2B', 1)})
    piencode = len(pipart.encode()).to_bytes(length=1, byteorder='big') + pipart.encode()
    secondpart = Serialize({
            'qname': (serializeme.PREFIX_LEN_NULL_TERM, ("boston","cs158b")),
            'qtype': ('2B', 1),
            'qclass': ('2B', 1),
            'aname': ('2B',49164),
            'atype': ('2B', 1),
            'aclass': ('2B', 1),
            'attl': ('4B', 299),
            'adata_length': ('2B', 4),
            'address': (serializeme.IPv4, f"172.16.2.{pinum}")
        })
    response = firstpart.packetize() + piencode + secondpart.packetize()
    return response

def ip_to_hostname(hostname, query):
    parts = hostname.split('.')
    pinum = parts[0]
    firstpart = Serialize({
            'ID': ('2B', query.get_field('ID').value),
            'pflags': ('2B', 33152),
            'qcnt': ('2B', 1),
            'acnt': ('2B', 1),
            'ncnt': ('2B', 0),
            'mcnt': ('2B', 0)
    })
    qpart = bytearray()
    for part in (query.get_field('qname').value).split('.'):
        qpart += bytearray([len(part)])
        qpart += str.encode(part)
    qpart += b'\x00'

    qpart += Serialize({
        'Type': ('2B', int(query.get_field('qtype').value)),
        'class': ('2B', int(query.get_field('qclass').value))
    }).packetize()

    answer = Serialize({
            'aname': ('2B',49164),
            'atype': ('2B', int(query.get_field('qtype').value)),
            'aclass': ('2B', 1),
            'attl': ('4B', 1821),
            'adata_length': ('2B', 20)
        })
    pipart = f"pi{pinum}"
    piencode = len(pipart.encode()).to_bytes(length=1, byteorder='big') + pipart.encode()
    secondpart = Serialize({
            'qname': (serializeme.PREFIX_LEN_NULL_TERM, ("boston","cs158b"))
    })
    result = firstpart.packetize() + qpart+ answer.packetize() + piencode + secondpart.packetize()
    return result

def read_piman_yml():
    domain, servers = '', []
    with open('./piman.yaml') as rf:
        for line in rf.readlines():
            if 'dns_domain' in line:
                domain = line.split(':')[-1].strip()
            elif 'dns_servers' in line:
                for server in line.split(':')[-1].split(','):
                    servers.append(server.strip())
        return domain, servers

def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((IP, PORT))
    print("DNS Listening on {0}:{1} ...".format(IP, PORT))
    while True:
        data, address = sock.recvfrom(1024)
        rsp = doDNS(data)
        sock.sendto(rsp, address)

if __name__ == '__main__':
    main()
