#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
@author: Amogha Kagal Jayaprakash

Usage: python chord_node.py PORT 
(if PORT is 0, program starts a new network,
otherwise it attempts to join an existing chord network where one of the nodes is running at PORT)

M = hashlib.sha1().digest_size * 8 which is = 160, 
the number of NODES would be 1461501637330902918203684832716283019655932542976
and I faced "truncated" issues with pickling and unpickling.
So I have set M = 3, and it works perfectly fine.

For the output, the program displays the snapshot of the node's information(id, finger table, successor and predecessor)
and keys every 5 seconds. (first state displayed will be before joining the chord network)


References and Inspiration: Prof Kevin Lundeen
"""

import socket
import pickle
from datetime import datetime
import sys
import hashlib
import threading
from threading import Timer

M = hashlib.sha1().digest_size * 8
NODES = 2**M
BUF_SZ = 20000  # socket recv arg
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
    
    SUCCESSOR = 'successor'
    PREDECESSOR = 'predecessor'
    SET_PREDECESSOR = 'set_predecessor'
    FIND_SUCCESSOR = 'find_successor'
    CLOSEST_PRECEDING_FINGER = 'closest_preceding_finger'
    UPDATE_FINGER_TABLE = 'update_finger_table'   
    POPULATE_CHORD = 'populate_chord'
    FIND_NODE_TO_PLACE_KEY = 'find_node_to_place_key'
    NODE_PLACE_KEY = 'node_place_key'
    CHORD_QUERY = 'chord_query'
    FIND_NODE_TO_QUERY_KEY = 'find_node_to_query_key'
    NODE_QUERY_KEY = 'node_query_key'
    GET_KEYS_TO_REDISTRIBUTE = 'get_keys_to_redistribute'
    
    DISPLAY_TIME_INTERVAL = 5
    
    def __init__(self):
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
        return self.call_rpc(np['address'], ChordNode.SUCCESSOR)
    
    def find_predecessor(self, id):
        """ Ask this node to find id's predecessor = predecessor(closest_preceding_finger(id))"""
        np = self.node
        np_succ = self.call_rpc(np['address'], ChordNode.SUCCESSOR)
        while id not in ModRange((np['id'] + 1) % NODES, (np_succ['id'] + 1) % NODES, NODES):
            np = self.call_rpc(np['address'], ChordNode.CLOSEST_PRECEDING_FINGER, [id])
            np_succ = self.call_rpc(np['address'], ChordNode.SUCCESSOR)
        return np
    
    def closest_preceding_finger(self, id):
        """" Returns closest preceding finger if present else return node """
        for i in range(M, 0, -1):
            if self.finger[i].node['id'] in ModRange((self.node['id'] + 1) % NODES, id, NODES):
                return self.finger[i].node
        return self.node
    
    def join(self, np):
        """ if node is joining to already existing chord then update other nodes """
        """ if not move key in (predecessor,node] """
        if np[1] != 0:
            self.init_finger_table(np)
            self.update_others()  
            self.redistribute_keys()
        else:
            for i in range(1, M+1):
                self.finger[i].node = self.node
            self.predecessor = self.node
    
    def init_finger_table(self, np):
        """ init finger table function """
        self.finger[1].node = self.call_rpc(np, ChordNode.FIND_SUCCESSOR, [self.finger[1].start])
        self.predecessor = self.call_rpc(self.successor['address'], ChordNode.PREDECESSOR)
        self.call_rpc(self.successor['address'], ChordNode.SET_PREDECESSOR, [self.node])
        for i in range(1, M):
            if self.finger[i+1].start in ModRange(self.node['id'], self.finger[i].node['id'], NODES):
                self.finger[i+1].node = self.finger[i].node
            else:
                self.finger[i+1].node = self.call_rpc(np, ChordNode.FIND_SUCCESSOR, [self.finger[i+1].start])
    
    def update_others(self):
        """ This function updates the already existing nodes everytime new node joins the chord by calling RPC function """
        for i in range(1, M+1):
            #p = self.find_predecessor(self.node - (2**(i-1)))
            p = self.find_predecessor((1 + self.node['id'] - 2**(i-1) + NODES) % NODES)
            self.call_rpc(p['address'], ChordNode.UPDATE_FINGER_TABLE, [self.node, i])
            
    def update_finger_table(self, s, i):
        """ if s is i-th finger of n, update this node's finger table with s """
        if (self.finger[i].start != self.finger[i].node['id']  # FIXME: don't want e.g. [1, 1) which is the whole circle
                and s['id'] in ModRange(self.finger[i].start, self.finger[i].node['id'], NODES)):  # FIXME: bug in paper, [.start
            #print('update_finger_table({},{}): {}[{}] = {} since {} in [{},{})'.format(s, i, self.node, i, s, s,
            #                                                                          self.finger[i].start,
            #                                                                         self.finger[i].node))
            self.finger[i].node = s
            p = self.predecessor  # get first node preceding myself
            self.call_rpc(p['address'], ChordNode.UPDATE_FINGER_TABLE, [s, i])
            return self.node
        return 'did nothing {}'.format(self.node)
    
    def redistribute_keys(self):
        """ Redistributing the keys if new node joins. From its successor remove all the keys less than new node
        and add it to new node """
        keys = self.call_rpc(self.successor['address'], ChordNode.GET_KEYS_TO_REDISTRIBUTE, [self.node['id']])
        for key in keys:
            self.keys[key] = keys[key]

    def get_keys_to_redistribute(self, id):
        keys_to_redistribute = {}
        for key in self.keys:
            if key in ModRange((self.node['id'] + 1) % NODES, (id + 1) % NODES, NODES):
                keys_to_redistribute[key] = self.keys[key]
        for key in keys_to_redistribute:
            del self.keys[key]
        return keys_to_redistribute
                
    def populate_chord(self, data):
        for key in data:
            self.find_node_to_place_key(key, data[key])
        return 'populate_chord done'
            
    def find_node_to_place_key(self, key, value):
        """ if key not equals to node, then find the range from its finger table and call RPC """
        if key == self.node['id']:
            self.node_place_key(key, value)
        else:
            #check interval
            for k in range(1, M+1):
                if key in self.finger[k].interval:
                    if key in ModRange(self.finger[k].start, (self.finger[k].node['id'] + 1) % NODES, NODES):
                        self.call_rpc(self.finger[k].node['address'], ChordNode.NODE_PLACE_KEY, [key, value])
                    else:
                        self.call_rpc(self.finger[k].node['address'], ChordNode.FIND_NODE_TO_PLACE_KEY, [key, value])
                    break;
        return 'find_node_to_place_key done'
    
    def node_place_key(self, key, value):
        self.keys[key] = value
        return 'node_place_key for ' + str(key) + ' done at node ' + str(self.node['id'])
    
    def chord_query(self, key):
        return self.find_node_to_query_key(key)
            
    def find_node_to_query_key(self, key):
        """ This function is same as find_node_to_place_key, except it returns the key values """
        if key in self.keys:
            return self.node_query_key(key)
        else:
            #check interval
            for k in range(1, M+1):
                if key in self.finger[k].interval:
                    if key in ModRange(self.finger[k].start, (self.finger[k].node['id'] + 1) % NODES, NODES):
                        return self.call_rpc(self.finger[k].node['address'], ChordNode.NODE_QUERY_KEY, [key])
                    else:
                        return self.call_rpc(self.finger[k].node['address'], ChordNode.FIND_NODE_TO_QUERY_KEY, [key])
                    break;
        return None
    
    def node_query_key(self, key):
        return self.keys[key]
                    
    def startup(self):
        self.listener_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener_sock.bind(('localhost', 0))
        self.listener_sock.listen(BACKLOG)

    def call_rpc(self, destination, method, arguments=[]):
        if destination == self.node['address']:
            return self.dispatch_rpc(method, arguments)
        else:
            data = None
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                try:
                    s.connect(destination)
                    s.sendall(self.pickle_message((method, arguments)))
                    data = s.recv(BUF_SZ)
                    return self.unpickle_message(data)
                except Exception as e:
                    print('Failed to connect: ', e)
                    return None
                finally:
                    s.close()
            return data
    
    def handle_rpc(self, client):
        data = client.recv(BUF_SZ)
        method, arguments = pickle.loads(data)
        print('method : ', method, 'arguments : ', arguments)
        result = self.dispatch_rpc(method, arguments)
        client.sendall(pickle.dumps(result))
        client.close()
    
    def dispatch_rpc(self, method, arguments):
        if method == ChordNode.FIND_SUCCESSOR:
            return self.find_successor(arguments[0])
        if method == ChordNode.SUCCESSOR:
            return self.successor
        if method == ChordNode.PREDECESSOR:
            return self.predecessor
        if method == ChordNode.SET_PREDECESSOR:
            self.predecessor = arguments[0]
            return "Set Predecessor Done"
        if method == ChordNode.CLOSEST_PRECEDING_FINGER:
            return self.closest_preceding_finger(arguments[0])
        if method == ChordNode.UPDATE_FINGER_TABLE:
            return self.update_finger_table(arguments[0], arguments[1])
        if method == ChordNode.POPULATE_CHORD:
            return self.populate_chord(arguments[0])
        if method == ChordNode.FIND_NODE_TO_PLACE_KEY:
            return self.find_node_to_place_key(arguments[0], arguments[1])
        if method == ChordNode.NODE_PLACE_KEY:
            return self.node_place_key(arguments[0], arguments[1])
        if method == ChordNode.CHORD_QUERY:
            return self.chord_query(arguments[0])
        if method == ChordNode.FIND_NODE_TO_QUERY_KEY:
            return self.find_node_to_query_key(arguments[0])
        if method == ChordNode.NODE_QUERY_KEY:
            return self.node_query_key(arguments[0])
        if method == ChordNode.GET_KEYS_TO_REDISTRIBUTE:
            return self.get_keys_to_redistribute(arguments[0])
        
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

    def display(self):
        print(f'\nSnapshot of Node details: {ChordNode.format_time()}')
        print('Node: ', self.node)
        print('Finger Table: ')
        for k in range(1, M+1):
            print('Start: ', node.finger[k].start, ', Interval: [',  node.finger[k].interval.start, ', ', node.finger[k].interval.stop, '), Node: ', node.finger[k].node)
        print('Predecessor: ', node.predecessor)
        print('Successor: ', node.successor)
        
        print('\nKeys present in node:')
        if not self.keys:
            print('Empty Keys')
        for k in self.keys:
            print('key: ', k, 'in node: ', self.node['id'])

        Timer(ChordNode.DISPLAY_TIME_INTERVAL, self.display).start()
        
    def run(self):
        try:
            while True:
                conn, addr = self.listener_sock.accept()
                threading.Thread(target=self.handle_rpc, args=(conn,)).start()
        except KeyboardInterrupt:
            self.close_listener_sock()
            print('\nClosed Listening Socket')

if __name__ == '__main__':
    
    if len(sys.argv) != 2:
        print("Usage: python chord_node.py PORT")
        exit(1)
    
    port_number = (int(sys.argv[1]))
    
    node = ChordNode()
    joining_node = (node.node['address'][0], port_number)
    threading.Thread(target=node.join, args=(joining_node,)).start()
    node.display()
    node.run()