#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Fri Nov 15 20:05:30 2019

@author: amogha
"""

import selectors
import socket
import pickle
from datetime import datetime
import sys
import hashlib

M = 3  # FIXME: Test environment, normally = hashlib.sha1().digest_size * 8
NODES = 2**M
BUF_SZ = 4096  # socket recv arg
BACKLOG = 100  # socket listen arg
TEST_BASE = 43544  # for testing use port numbers on localhost at TEST_BASE+n

class ModRange(object):
    """
    Range-like object that wraps around 0 at some divisor using modulo arithmetic.

    >>> mr = ModRange(1, 4, 100)
    >>> mr
    
    >>> 1 in mr and 2 in mr and 4 not in mr
    True
    >>> [i for i in mr]
    [1, 2, 3]
    >>> mr = ModRange(97, 2, 100)
    >>> 0 in mr and 99 in mr and 2 not in mr and 97 in mr
    True
    >>> [i for i in mr]
    [97, 98, 99, 0, 1]
    """

    def __init__(self, start, stop, divisor):
        self.divisor = divisor
        self.start = start % self.divisor
        self.stop = stop % self.divisor
        # we want to use ranges to make things speedy, but if it wraps around the 0 node, we have to use two
        if self.start < self.stop:
            self.intervals = (range(self.start, self.stop),)
        else:
            self.intervals = (range(self.start, self.divisor), range(0, self.stop))

    def __repr__(self):
        """ Something like the interval|node charts in the paper """
        return ''.format(self.start, self.stop, self.divisor)

    def __contains__(self, id):
        """ Is the given id within this finger's interval? """
        for interval in self.intervals:
            if id in interval:
                return True
        return False

    def __len__(self):
        total = 0
        for interval in self.intervals:
            total += len(interval)
        return total

    def __iter__(self):
        return ModRangeIter(self, 0, -1)


class ModRangeIter(object):
    """ Iterator class for ModRange """
    def __init__(self, mr, i, j):
        self.mr, self.i, self.j = mr, i, j

    def __iter__(self):
        return ModRangeIter(self.mr, self.i, self.j)

    def __next__(self):
        if self.j == len(self.mr.intervals[self.i]) - 1:
            if self.i == len(self.mr.intervals) - 1:
                raise StopIteration()
            else:
                self.i += 1
                self.j = 0
        else:
            self.j += 1
        return self.mr.intervals[self.i][self.j]


class FingerEntry(object):
    """
    Row in a finger table.

    >>> fe = FingerEntry(0, 1)
    >>> fe
    
    >>> fe.node = 1
    >>> fe
    
    >>> 1 in fe, 2 in fe
    (True, False)
    >>> FingerEntry(0, 2, 3), FingerEntry(0, 3, 0)
    (, )
    >>> FingerEntry(3, 1, 0), FingerEntry(3, 2, 0), FingerEntry(3, 3, 0)
    (, , )
    >>> fe = FingerEntry(3, 3, 0)
    >>> 7 in fe and 0 in fe and 2 in fe and 3 not in fe
    True
    """
    def __init__(self, n, k, node=None):
        if not (0 <= n < NODES and 0 < k <= M):
            raise ValueError('invalid finger entry values')
        self.start = (n + 2**(k-1)) % NODES
        self.next_start = (n + 2**k) % NODES if k < M else n
        self.interval = ModRange(self.start, self.next_start, NODES)
        self.node = node

    def __repr__(self):
        """ Something like the interval|node charts in the paper """
        return ''.format(self.start, self.next_start, self.node)

    def __contains__(self, id):
        """ Is the given id within this finger's interval? """
        return id in self.interval


class ChordNode(object):
    
    def __init__(self):
        self.selector = selectors.DefaultSelector()
        self.startup()
        self.node = {}
        self.node['id'] = ChordNode.hash_sha1(self.listener_sock.getsockname()) % NODES
        self.node['address'] = self.listener_sock.getsockname()
        self.finger = [None] + [FingerEntry(self.node['id'], k) for k in range(1, M+1)]  # indexing starts at 1
        self.predecessor = None
        self.keys = {}
        
    @property
    def successor(self):
        return self.finger[1].node
    
    @successor.setter
    def successor(self, successor_node):
        self.finger[1].node = successor_node
    
    def find_successor(self, id):
        """ Ask this node to find id's successor = successor(predecessor(id))"""
        np = self.find_predecessor(id)
        return self.call_rpc(np, 'successor')
    
    def find_predecessor(self, id):
        np = self.node
        while id not in ModRange(np['id'], self.call_rpc(np, 'successor')[0], NODES):
            np = self.call_rpc(np, 'closest_preceding_finger', [id])
        return np
    
    def closest_preceding_finger(self, id):
        for i in range(M, 0, -1):
            if self.finger[i].node['id'] in ModRange(self.node['id'], id, NODES):
                return self.finger[i].node
        return self.node
    
    def join(self, np):
        print('Init Finger Table : ', np[1])
        if np[1] != 0:
            self.init_finger_table(np)
            self.update_others()
        else:
            for i in range(1, M+1):
                self.finger[i].node = self.node
            self.predecessor = self.node
    
    def init_finger_table(self, np):
        self.finger[1].node = self.call_rpc(np, 'find_successor', [self.finger[1].start])
        self.predecessor = self.call_rpc(self.successor['address'], 'predecessor')
        for i in range(1, M):
            if self.finger[i+1].start in ModRange(self.node['id'], self.finger[i].node['id'], NODES):
                self.finger[i+1].node = self.finger[i].node
            else:
                self.finger[i+1].node = self.call_rpc(np, 'find_successor', [self.finger[i+1].start])
    
    def update_others(self):
        for i in range(1, M+1):
            #p = self.find_predecessor(self.node - (2**(i-1)))
            p = self.find_predecessor((1 + self.node - 2**(i-1) + NODES) % NODES)
            self.call_rpc(p, 'update_finger_table', [self.node, i])

    def update_finger_table(self, s, i):
        if self.finger[i].start != self.finger[i].node['id'] and s in ModRange(self.node['id'], self.finger[i].node['id'], NODES):
            self.finger[i].node = s
            p = self.predecessor
            self.call_rpc(p['address'], 'update_finger_table', [s, i])

    def startup(self):
        self.listener_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener_sock.bind(('localhost', 0))
        self.listener_sock.setblocking(0)
        self.listener_sock.listen()
        self.selector.register(self.listener_sock, selectors.EVENT_READ | selectors.EVENT_WRITE)

    def call_rpc(self, destination, function_name, parameters):
        self.connect_peer(destination, (function_name, parameters))        
        
    def accept_peer(self):
        print('Accepting')
        conn, addr = self.listener_sock.accept()
        conn.setblocking(False)
        self.selector.register(conn, selectors.EVENT_READ | selectors.EVENT_WRITE)

    def receive_message(self, conn):
        print('Receiving')
        data = conn.recv(1024)
        if data:
            received_data = self.unpickle_message(data)
            message, members = received_data
        self.selector.unregister(conn)
        conn.close()
            
    def connect_peer(self, peer, message):
        print('Connecting')
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setblocking(False)
        sock.connect_ex(peer)
        self.selector.register(sock, selectors.EVENT_WRITE, data=message)
        
    def send_message(self, conn, message):
        print('Sending')
        try:
            conn.sendall(self.pickle_message(message))
            self.selector.modify(conn, selectors.EVENT_READ)
        except Exception:
            self.selector.unregister(conn)
            conn.close()
    
    def pickle_message(self, message):
        return pickle.dumps(message)

    def unpickle_message(self, message):
        return pickle.loads(message)
    
    def close_listener_sock(self):
        self.listener_sock.close()
    
    @staticmethod
    def hash_sha1(data):
        return int(hashlib.sha1(pickle.dumps(data)).hexdigest(), 16)
    
    @staticmethod
    def format_time():
        return datetime.now().strftime('%H:%M:%S.%f')

    def run(self):
        try:
            while True:
                events = self.selector.select()
                for key, mask in events:
                    print('Event received from : ', key.fileobj)
                    if key.fileobj == self.listener_sock:
                        self.accept_peer()
                    elif mask & selectors.EVENT_READ:
                        self.receive_message(key.fileobj)
                    elif key.data and mask & selectors.EVENT_WRITE:
                        self.send_message(key.fileobj, key.data)
                        
        except KeyboardInterrupt:
            self.close_listener_sock()
            print('\nClosed Listening Socket')

if __name__ == '__main__':
    
    if len(sys.argv) != 2:
        print("Usage: python chord_node.py PORT")
        exit(1)
    
    port_number = (int(sys.argv[1]))
    
    node = ChordNode()
    node.startup()
    joining_node = (node.node['address'][0], port_number)
    node.join(joining_node)
    print('Node : ', node.node)
    print('Finger : ')
    for k in range(1, M+1):
        print('Start : ', node.finger[k].start, ', Interval : ',  node.finger[k].interval, ', Node : ', node.finger[k].node)
    print('Predecessor : ', node.predecessor)
    print('Successor : ', node.successor)
    node.run()
    
    
#63406 1,2,4