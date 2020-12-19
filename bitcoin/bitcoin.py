#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
@author: Amogha Kagal Jayaprakash

Usage: python lab5.py
The program starts off with connecting to Bitcoin P2P network node ('5.79.123.3', 8333)
Steps Completed:
    1. Send VERSION message and receive VERSION message.
    2. Send VERACK and receive VERACK
    3. Once connection is established program sends GETBLOCKS using the Genesis Block Hash
    4. Recieve INV message and save(display) all block hashes
    5. Request SU_ID % 500 block, using GETDATA
    6. Recieve BLOCK message and parse(display) the information

References and Inspiration: Prof Kevin Lundeen
"""

import socket
from time import gmtime,strftime
import time
import hashlib
import threading

HDR_SZ = 24

class Node():
    
    COMMAND_VERSION   = 'version'
    COMMAND_VERACK    = 'verack'
    COMMAND_GETBLOCKS = 'getblocks'
    COMMAND_INV       = 'inv'
    COMMAND_GETDATA   = 'getdata'
    COMMAND_BLOCK     = 'block'
    
    SU_ID = 4088931
    
    def __init__(self):
        self.destination_addr = ('5.79.123.3', 8333)
        self.block_header_hashes = []
        self.startup()
        
    def startup(self):
        self.sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        self.sock.connect(self.destination_addr)
        
    def call_rpc(self, command):
        """
        Sends message(built based on command) to bitcoin node
        """
        print('\nsending MESSAGE')
        self.sock.sendall(self.create_command_message(command))

    def handle_rpc(self, command, payload):
        """
        Based on command recieved, take appropriate action to achieve our goal
        """
        if command == Node.COMMAND_VERSION:
            self.call_rpc(Node.COMMAND_VERACK)
        if command == Node.COMMAND_VERACK:
            self.call_rpc(Node.COMMAND_GETBLOCKS)
        if command == Node.COMMAND_INV:
            self.call_rpc(Node.COMMAND_GETDATA)
        
    def create_command_message(self, command):
        """
        Based on command build the appropriate payload 
        and display the built header and payload
        """
        payload = b''
        if command == Node.COMMAND_VERSION:
            payload = self.create_version_payload()
        if command == Node.COMMAND_GETBLOCKS:
            payload = self.create_getblocks_payload()
        if command == Node.COMMAND_GETDATA:
            payload = self.create_getdata_payload()    
        header = self.create_header(command, payload)
        self.print_message(header + payload)
        return header + payload
    
    def create_header(self, command, payload):
        """
        Create header based on command and use payload to get payload size
        https://bitcoin.org/en/developer-reference#message-headers
        """
        start_string = bytes.fromhex("F9BEB4D9")
        command_name = str.encode(command) + (12 - len(command)) * b'\00'
        payload_size = Node.uint32_t(len(payload))
        checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
        header = start_string + command_name + payload_size + checksum
        return header
    
    def create_version_payload(self):
        """
        Create version payload
        https://bitcoin.org/en/developer-reference#version
        """
        version = Node.int32_t(70015)
        services = Node.uint64_t(0)
        timestamp = Node.int64_t(time.time())
        add_recv_services = Node.uint64_t(0)
        add_recv_ip = Node.ipv6_from_ipv4(self.destination_addr[0])
        add_recv_port = Node.uint16_t(self.destination_addr[1])
        add_trans_services = Node.uint64_t(0)
        add_trans_ip = Node.ipv6_from_ipv4(self.sock.getsockname()[0])
        add_trans_port = Node.uint16_t(self.sock.getsockname()[1])
        nonce = Node.uint64_t(0)
        user_agent = Node.compactsize_t(0)
        start_height = Node.int32_t(0)
        relay = Node.bool_t(False)
        payload = version + services + timestamp + add_recv_services + \
                add_recv_ip + add_recv_port + add_trans_services + \
                add_trans_ip + add_trans_port + nonce + user_agent + \
                start_height + relay
        
        return payload
    
    def create_getblocks_payload(self):
        """
        Create version payload
        https://bitcoin.org/en/developer-reference#getblocks
        """
        version = Node.int32_t(70015)
        hash_count = Node.compactsize_t(1)
        #Genesis block header hash
        header_hash = b'000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f'
        stop_hash = b'\00' * 32
        payload = version + hash_count + header_hash + stop_hash
        return payload
    
    def create_getdata_payload(self):
        """
        Create version payload
        https://bitcoin.org/en/developer-reference#getdata
        """
        count = Node.compactsize_t(1)
        index = Node.SU_ID % len(self.block_header_hashes)
        type_block = Node.uint32_t(self.block_header_hashes[index]['type'])
        block_hash = bytearray.fromhex(self.block_header_hashes[index]['hash'])
        payload = count + type_block + block_hash
        return payload
    
    def print_message(self, msg, text=None):
        """
        Report the contents of the given bitcoin message
        :param msg: bitcoin message including header
        :return: message type
        """
        print('{}MESSAGE'.format('' if text is None else (text + ' ')))
        print('({}) {}'.format(len(msg), msg[:60].hex() + ('' if len(msg) < 60 else '...')))
        payload = msg[HDR_SZ:]
        command, psz = self.parse_print_header(msg[:HDR_SZ], Node.checksum(payload))
        if command == Node.COMMAND_VERSION:
            self.print_version_msg(payload)
        if command == Node.COMMAND_INV:
            self.parse_print_inv_msg(payload)
        if command == Node.COMMAND_GETBLOCKS:
            self.parse_print_getblocks_msg(payload)
        if command == Node.COMMAND_GETDATA:
            self.parse_print_getdata_msg(payload)
        return command
    
    def print_version_msg(self, b):
        """
        Report the contents of the given bitcoin version message (sans the header)
        :param payload: version message contents
        """
        # pull out fields
        version, my_services, epoch_time, your_services = b[:4], b[4:12], b[12:20], b[20:28]
        rec_host, rec_port, my_services2, my_host, my_port = b[28:44], b[44:46], b[46:54], b[54:70], b[70:72]
        nonce = b[72:80]
        user_agent_size, uasz = Node.unmarshal_compactsize(b[80:])
        i = 80 + len(user_agent_size)
        user_agent = b[i:i + uasz]
        i += uasz
        start_height, relay = b[i:i + 4], b[i + 4:i + 5]
        extra = b[i + 5:]
    
        # print report
        prefix = '  '
        print(prefix + 'VERSION')
        print(prefix + '-' * 56)
        prefix *= 2
        print('{}{:32} version {}'.format(prefix, version.hex(), Node.unmarshal_int(version)))
        print('{}{:32} my services'.format(prefix, my_services.hex()))
        time_str = strftime("%a, %d %b %Y %H:%M:%S GMT", gmtime(Node.unmarshal_int(epoch_time)))
        print('{}{:32} epoch time {}'.format(prefix, epoch_time.hex(), time_str))
        print('{}{:32} your services'.format(prefix, your_services.hex()))
        print('{}{:32} your host {}'.format(prefix, rec_host.hex(), Node.ipv6_to_ipv4(rec_host)))
        print('{}{:32} your port {}'.format(prefix, rec_port.hex(), Node.unmarshal_uint(rec_port)))
        print('{}{:32} my services (again)'.format(prefix, my_services2.hex()))
        print('{}{:32} my host {}'.format(prefix, my_host.hex(), Node.ipv6_to_ipv4(my_host)))
        print('{}{:32} my port {}'.format(prefix, my_port.hex(), Node.unmarshal_uint(my_port)))
        print('{}{:32} nonce'.format(prefix, nonce.hex()))
        print('{}{:32} user agent size {}'.format(prefix, user_agent_size.hex(), uasz))
        print('{}{:32} user agent \'{}\''.format(prefix, user_agent.hex(), str(user_agent, encoding='utf-8')))
        print('{}{:32} start height {}'.format(prefix, start_height.hex(), Node.unmarshal_uint(start_height)))
        print('{}{:32} relay {}'.format(prefix, relay.hex(), bytes(relay) != b'\0'))
        if len(extra) > 0:
            print('{}{:32} EXTRA!!'.format(prefix, extra.hex()))
    
    def parse_print_getblocks_msg(self, b):
        """
        Report the contents of the given bitcoin inv message (sans the header)
        :param payload: getblocks message contents
        """
        version = Node.unmarshal_int(b[:4])
        bytes_used, hash_count = Node.unmarshal_compactsize(b[4:])
        #Genesis block header hash
        header_hash = b[4+len(bytes_used):4+len(bytes_used)+64].decode("utf-8") 
        stop_hash = b[4+len(bytes_used)+64:].decode("utf-8") 
        
        # print report
        prefix = '  '
        print(prefix + 'GETBLOCKS')
        print(prefix + '-' * 56)
        prefix *= 2
        print('{} Version:\t\t {}'.format(prefix, version))
        print('{} Hash Count:\t {}'.format(prefix, hash_count))
        print('{} Block Header Hash:\t {}'.format(prefix, header_hash))
        print('{} Stop Hash:\t {}'.format(prefix, stop_hash))
     
    def parse_print_getdata_msg(self, b):
        """
        Report the contents of the given bitcoin inv message (sans the header)
        :param payload: getdata message contents
        """
        count = 1
        index = Node.SU_ID % len(self.block_header_hashes)
        type_block = self.block_header_hashes[index]['type']
        block_hash = self.block_header_hashes[index]['hash']
        
        # print report
        prefix = '  '
        print(prefix + 'GETDATA')
        print(prefix + '-' * 56)
        prefix *= 2
        print('{} Count:\t\t {}'.format(prefix, count))
        print('{} Type:\t\t {}'.format(prefix, type_block))
        print('{} Block Header Hash:\t {}'.format(prefix, block_hash))
        
    def parse_print_inv_msg(self, b):
        """
        Report the contents of the given bitcoin inv message (sans the header)
        :param payload: inv message contents
        """
        bytes_used, count = Node.unmarshal_compactsize(b)
        for i in range(len(bytes_used), len(b), 36):
            type_block = Node.unmarshal_uint(b[i:i+4])
            hash_block = str(b[i+4:i+36].hex())
            self.block_header_hashes.append({'type':type_block, 'hash': hash_block})
        
        # print report
        prefix = '  '
        print(prefix + 'INV')
        print(prefix + '-' * 56)
        prefix *= 2
        print('{}{:32} count {}'.format(prefix, bytes_used.hex(), count))
        for header_hash in self.block_header_hashes:
            print('{} Type: {:2}\tHash: {:40}'.format(prefix, header_hash['type'], header_hash['hash']))
    
    def parse_print_block_msg(self, b):
        """
        Report the contents of the given bitcoin block message (sans the header)
        :param payload: block message contents
        """
        self.block = {'header': {}, 'transactions': []}
        transactions = []
        block_header = b[:80]
        version, prev_block_header_hash, merkle_root_hash, time, nBits, nonce = block_header[:4], block_header[4:36], \
                                    block_header[36:68], block_header[68:72], block_header[72:76], block_header[76:80]
        version = Node.unmarshal_int(version)
        prev_block_header_hash = str(prev_block_header_hash.hex())
        merkle_root_hash = str(merkle_root_hash.hex())
        time = Node.unmarshal_uint(time)
        nBits = Node.unmarshal_uint(nBits)
        nonce = Node.unmarshal_uint(nonce)
        
        self.block['header'] = {
                    'version': version,
                    'prev_block_header_hash': prev_block_header_hash,
                    'merkle_root_hash': merkle_root_hash,
                    'time': time,
                    'nBits': nBits,
                    'nonce': nonce
                }
        prefix = '  '
        print(prefix + 'BLOCK')
        print(prefix + '-' * 56)
        prefix *= 2
        print(prefix + 'BLOCK HEADER')
        print('{} Version:\t\t\t\t {}'.format(prefix, self.block['header']['version']))
        print('{} Previous Block Header Hash:\t {}'.format(prefix, self.block['header']['prev_block_header_hash']))
        print('{} Merkle Root Hash:\t\t\t {}'.format(prefix, self.block['header']['merkle_root_hash']))
        print('{} Time:\t\t\t\t {}'.format(prefix, self.block['header']['time']))
        print('{} nBits:\t\t\t\t {}'.format(prefix, self.block['header']['nBits']))
        print('{} Nonce:\t\t\t\t {}'.format(prefix, self.block['header']['nonce']))
        
        bytes_used, txn_count = Node.unmarshal_compactsize(b[80:])
        transaction_data = b[80+len(bytes_used):]
        current_bytes_pointer_offset = 0
        for i in range(0, txn_count):
            
            version = Node.unmarshal_int(transaction_data[current_bytes_pointer_offset:current_bytes_pointer_offset + 4])
            current_bytes_pointer_offset += 4
            
            bytes_used, tx_in_count = Node.unmarshal_compactsize(transaction_data[current_bytes_pointer_offset:])
            current_bytes_pointer_offset += len(bytes_used)
            
            bytes_used_tx_in, tx_in  = self.get_txIn(transaction_data[current_bytes_pointer_offset:], tx_in_count)
            current_bytes_pointer_offset += bytes_used_tx_in
            
            bytes_used, tx_out_count = Node.unmarshal_compactsize(transaction_data[current_bytes_pointer_offset:])
            current_bytes_pointer_offset += len(bytes_used)
            
            bytes_used_tx_out, tx_out = self.get_txOut(transaction_data[current_bytes_pointer_offset:], tx_out_count)
            current_bytes_pointer_offset += bytes_used_tx_out
            
            lock_time = Node.unmarshal_uint(transaction_data[current_bytes_pointer_offset:current_bytes_pointer_offset+4])
            current_bytes_pointer_offset += 4
            
            tx = {
                "version": version,
                "tx_in_count": tx_in_count,
                "tx_in": tx_in,
                "tx_out_count": tx_out_count,
                "tx_out": tx_out,
                "lock_time": lock_time,
            }
            transactions.append(tx)
        
        self.block['transactions'] = transactions
        # print report
        prefix = '  '
        print(prefix + '-' * 56)
        prefix *= 2
        print(prefix + 'TRANSACTIONS')
        for transaction in self.block['transactions']:
            print('{} Version:\t\t\t\t {}'.format(prefix, transaction['version']))
            print('{} Transaction Input Count:\t\t {}'.format(prefix, transaction['tx_in_count']))
            print('{} Transaction Inputs:'.format(prefix))
            index = 0
            for transaction_inputs in transaction['tx_in']:
                index += 1
                print('{} Transaction Input {}:'.format(prefix*2, index))
                print('{} Hash:\t\t\t {}'.format(prefix*3, transaction_inputs['hash']))
                print('{} index:\t\t\t {}'.format(prefix*3, transaction_inputs['index']))
                print('{} script_bytes:\t\t {}'.format(prefix*3, transaction_inputs['script_bytes']))
                print('{} signature_script:\t\t {}'.format(prefix*3, transaction_inputs['signature_script']))
                print('{} sequence:\t\t\t {}'.format(prefix*3, transaction_inputs['sequence']))
            print('{} Transaction Output Count:\t\t {}'.format(prefix, transaction['tx_out_count']))
            print('{} Transaction Outputs:'.format(prefix))
            index = 0
            for transaction_outputs in transaction['tx_out']:
                index += 1
                print('{} Transaction Output {}:'.format(prefix*2, index))
                print('{} value:\t\t\t {}'.format(prefix*3, transaction_outputs['value']))
                print('{} pub_key_script_bytes:\t {}'.format(prefix*3, transaction_outputs['pub_key_script_bytes']))
                print('{} pk_script:\t\t\t {}'.format(prefix*3, transaction_outputs['pk_script']))
            print('{} Lock Time:\t\t\t\t {}'.format(prefix, transaction['lock_time']))
            
    def get_txIn(self,payload,tx_in_count):
        """
        Retrieve the contents of the given bitcoin block message's Transaction Inputs
        """
        tx_in = []
        current_bytes_pointer_offset = 0
        for i in range(0,tx_in_count):

            # previous_output
            hash_tx_in = str(payload[current_bytes_pointer_offset : current_bytes_pointer_offset + 32].hex())
            current_bytes_pointer_offset += 32
            
            index = Node.unmarshal_uint(payload[current_bytes_pointer_offset: current_bytes_pointer_offset + 4])
            current_bytes_pointer_offset += 4
            
            bytes_used, script_bytes = Node.unmarshal_compactsize(payload[current_bytes_pointer_offset:])
            current_bytes_pointer_offset += len(bytes_used)            
            
            signature_script = str(payload[current_bytes_pointer_offset : current_bytes_pointer_offset + script_bytes].hex())
            current_bytes_pointer_offset += script_bytes

            sequence = Node.unmarshal_uint(payload[current_bytes_pointer_offset:current_bytes_pointer_offset + 4])
            current_bytes_pointer_offset += 4

            tx_in.append({
                "hash":hash_tx_in,
                "index":index,
                "script_bytes": script_bytes,
                "signature_script": signature_script,
                "sequence": sequence,
            })

        return current_bytes_pointer_offset, tx_in
    
    def get_txOut(self,payload,tx_out_count):
        """
        Retrieve the contents of the given bitcoin block message's Transaction Outputs
        """
        tx_out = []
        current_bytes_pointer_offset = 0
        
        for i in range(0,tx_out_count):
            value = Node.unmarshal_int(payload[current_bytes_pointer_offset : current_bytes_pointer_offset+8])
            current_bytes_pointer_offset += 8
            
            bytes_used, pub_key_script_bytes = Node.unmarshal_compactsize(payload[current_bytes_pointer_offset:])
            current_bytes_pointer_offset += current_bytes_pointer_offset + len(bytes_used)
            
            pk_script = str(payload[current_bytes_pointer_offset : current_bytes_pointer_offset + pub_key_script_bytes].hex())
            current_bytes_pointer_offset += current_bytes_pointer_offset + pub_key_script_bytes
            
            tx_out.append({
                "value": value,
                "pub_key_script_bytes": pub_key_script_bytes,
                "pk_script": pk_script,
            })

        return current_bytes_pointer_offset, tx_out
        
    def parse_print_header(self, header, expected_cksum=None):
        """
        Report the contents of the given bitcoin message header
        :param header: bitcoin message header (bytes or bytearray)
        :param expected_cksum: the expected checksum for this version message, if known
        :return: message type
        """
        magic, command_hex, payload_size, cksum = header[:4], header[4:16], header[16:20], header[20:]
        command = str(bytearray([b for b in command_hex if b != 0]), encoding='utf-8')
        psz = Node.unmarshal_uint(payload_size)
        if expected_cksum is None:
            verified = ''
            
        elif expected_cksum == cksum:
            verified = '(verified)'
        else:
            verified = '(WRONG!! ' + expected_cksum.hex() + ')'
        prefix = '  '
        print(prefix + 'HEADER')
        print(prefix + '-' * 56)
        prefix *= 2
        print('{}{:32} magic'.format(prefix, magic.hex()))
        print('{}{:32} command: {}'.format(prefix, command_hex.hex(), command))
        print('{}{:32} payload size: {}'.format(prefix, payload_size.hex(), psz))
        print('{}{:32} checksum {}'.format(prefix, cksum.hex(), verified))
        return command, psz
    
    def parse_print_payload(self, command, payload, text=None):
        """
        Report the contents of the given bitcoin message
        :param msg: bitcoin message including header
        :return: message type
        """
        if command == Node.COMMAND_VERSION:
            self.print_version_msg(payload)
        if command == Node.COMMAND_INV:
            self.parse_print_inv_msg(payload)
        if command == Node.COMMAND_BLOCK:
            self.parse_print_block_msg(payload)
        return command
    
    @staticmethod
    def compactsize_t(n):
        if n < 252:
            return Node.uint8_t(n)
        if n < 0xffff:  
            return Node.uint8_t(0xfd) + Node.uint16_t(n)
        if n < 0xffffffff:
            return Node.uint8_t(0xfe) + Node.uint32_t(n)
        return Node.uint8_t(0xff) + Node.uint64_t(n)
    
    @staticmethod
    def unmarshal_compactsize(b):
        key = b[0]
        if key == 0xfd:
            return b[0:3], Node.unmarshal_uint(b[1:3])
        if key == 0xff:
            return b[0:9],Node.unmarshal_uint(b[1:9])
        if key == 0xfe:
            return b[0:5], Node.unmarshal_uint(b[1:5])
        return b[0:1], Node.unmarshal_uint(b[0:1])
    
    @staticmethod
    def bool_t(flag):
        return Node.uint8_t(1 if flag else 0)
    
    @staticmethod
    def ipv6_from_ipv4(ipv4_str):
        pchIPv4 = bytearray([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff])
        return pchIPv4 + bytearray((int(x) for x in ipv4_str.split('.')))
    
    @staticmethod
    def ipv6_to_ipv4(ipv6):
        return '.'.join([str(b) for b in ipv6[12:]])
    
    @staticmethod
    def uint8_t(n):
        return int(n).to_bytes(1, byteorder='little', signed=False)
    
    @staticmethod
    def uint16_t(n):
        return int(n).to_bytes(2, byteorder='little', signed=False)
    
    @staticmethod
    def int32_t(n):
        return int(n).to_bytes(4, byteorder='little', signed=True)
    
    @staticmethod
    def uint32_t(n):
        return int(n).to_bytes(4, byteorder='little', signed=False)
    
    @staticmethod
    def int64_t(n):
        return int(n).to_bytes(8, byteorder='little', signed=True)
    
    @staticmethod
    def uint64_t(n):
        return int(n).to_bytes(8, byteorder='little', signed=False)
    
    @staticmethod
    def unmarshal_int(b):
        return int.from_bytes(b, byteorder='little', signed=True)
    
    @staticmethod
    def unmarshal_uint(b):
        return int.from_bytes(b, byteorder='little', signed=False)
    
    @staticmethod
    def checksum(payload):
        return None
    
    def close_sock(self):
        self.sock.close()
        
    def run(self):
        try:
            while True:
                header = self.sock.recv(24)
                print('\nrecieved Message')
                print('MESSAGE')
                command, psz = self.parse_print_header(header)
                # get the payload
                payload = self.recvall(psz)
                self.parse_print_payload(command, payload)
                threading.Thread(target=self.handle_rpc, args=(command, payload)).start()
        except KeyboardInterrupt:
            self.close_sock()
            print('\nClosed Socket')
    
    def recvall(self, payload_size):
        payload_blocks = []
        while payload_size > 0:
            payload_block = self.sock.recv(payload_size)
            payload_blocks.append(payload_block)
            payload_size -= len(payload_block)
        return b''.join(payload_blocks)

if __name__ == '__main__':
    node = Node()
    threading.Thread(target=node.run, args=()).start()
    node.call_rpc(Node.COMMAND_VERSION)