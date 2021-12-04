# SJSU CS 158B Spring 2021
# Prof. Ben Reed
# Assignment 1
# Author: Le Duy Vu

import socket
import struct
import click


# click set up
@click.command()
@click.argument('server')
@click.argument('address')


# main function
def resolve(server, address):
    """
    This program sends a query to a DNS server based on the input arguments from the command line.
    If given a website name, it returns the web's IPv4 and IPv6 (if available) addresses.
    If given an IPv4 address, it returns the website name at that address.
    """

    # set up socket
    soc = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    soc.connect((server, 53))  # connect at port 53 for DNS

    # set up header
    id = 3
    flags = 1 << 8
    header = struct.pack('!6H', id, flags, 1, 0, 0, 0)

    # section size calculation
    headerSize = 12
    qnameSize = len(address) + 2  # 1 for the 1st length octet of the 1st label and 1 for null termination
    headerQuestionSize = headerSize + qnameSize + 4

    # prepare address to be encoded
    labels = address.split('.')
    question = b''

    # check if address is IP address or website
    if checkIPAddress(address):  # if IP address, look for website name
        # set up QNAME in question section
        labels.reverse()  # reverse the labels for PTR query
        for label in labels:
            question += bytes([len(label)]) + label.encode()  # turn labels into binaries and add length octet
        question += bytes([len("in-addr")]) + "in-addr".encode()
        question += bytes([len("arpa")]) + "arpa".encode()
        question += b'\0\0' + bytes([12]) + b'\0\1'  # type PTR class IN

        # send and receive
        soc.send(header + question)
        response = soc.recv(1024)
        headerQuestionSize += 13  # for .in-addr.arpa
        answerSection = response[headerQuestionSize:]

        # extract website name
        if int(struct.unpack('!H', response[6:8])[0]):  # if an answer comes back
            rdlength = int(struct.unpack('!H', answerSection[10:12])[0])  # length of data in bytes
            form = '!' + str(rdlength) + 'B'
            rdata = struct.unpack(form, answerSection[12:(12 + rdlength)])  # extract rdata field
            website = ''

            i = 0
            # build the website name based on rdata
            while i < rdlength:
                for j in range(rdata[i]):
                    website += chr(rdata[i + 1 + j])  # convert each byte into ascii char
                website += '.'  # add dot separating domains
                i += rdata[i] + 1
            website = website[:-2]  # delete trailing dots
            print(website)
        else:
            print('website not found')

    else:  # if website name, look for IP addresses
        # set up QNAME in question section
        for label in labels:
            question += bytes([len(label)]) + label.encode()  # turn labels into binaries and add length octet
        # IPv4
        v4Tail = b'\0\0\1\0\1'  # type A class IN
        v4Question = question + v4Tail

        # send and receive
        soc.send(header + v4Question)
        response = soc.recv(1024)
        answerCount = int(struct.unpack('!H', response[6:8])[0])
        answerSection = response[headerQuestionSize:]

        # extract IPv4 address
        if answerCount:
            for i in range(answerCount):
                offset = i * 16  # size of an answer record
                (a, b, c, d) = struct.unpack('!4B', answerSection[(offset + 12):(offset + 16)])
                print(f'{a}.{b}.{c}.{d}')
        else:
            print('IPv4 address not found')

        # IPv6
        v6Tail = b'\0\0' + bytes([28]) + b'\0\1'  # type AAAA class IN
        v6Question = question + v6Tail

        # send and receive
        soc.send(header + v6Question)
        response = soc.recv(1024)
        answerCount = int(struct.unpack('!H', response[6:8])[0])
        answerSection = response[headerQuestionSize:]

        # extract IPv6 address
        if answerCount:
            for i in range(answerCount):
                offset = i * 28  # size of an answer record
                (a, b, c, d, e, f, g, h) = struct.unpack('!8H', answerSection[(offset + 12):(offset + 28)])
                print(f"{format(a, 'x')}:{format(b, 'x')}:" +
                      f"{format(c, 'x')}:{format(d, 'x')}:" +
                      f"{format(e, 'x')}:{format(f, 'x')}:" +
                      f"{format(g, 'x')}:{format(h, 'x')}")
        else:
            print('IPv6 address not found')


# helper function to check if the address given is a website name or an IP address
def checkIPAddress(addr):
    parts = addr.split('.')  # split the addr to parts separated by .
    # condition for a correct IPv4 address
    if addr.count('.') == 3 and all(checkInt(part) for part in parts):
        return True
    return False


# helper function to check if a string is an integer between 0 and 255, included
def checkInt(s):
    try:
        return str(int(s)) == s and 0 <= int(s) <= 255
    except:
        return False


if __name__ == '__main__':
    resolve()
