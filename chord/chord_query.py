#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
@author: Amogha Kagal Jayaprakash

Usage: python chord_query.py PORT QUERY
(the program attempts to query data from an existing chord network where one of the nodes is running at PORT)
(QUERY is formed by concatinating PLAYER_ID and YEAR, example tomfarris/25138611948)
"""

import hashlib
import pickle
import socket
import sys
from chord_node import NODES, BUF_SZ

class ChordQuery(object):
    
    CHORD_QUERY = 'chord_query'

    @staticmethod
    def hash_sha1(data):
       return int(hashlib.sha1(pickle.dumps(data)).hexdigest(), 16)
   
    def call_rpc(self, destination, method, arguments=[]):
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
   
    def pickle_message(self, message):
        return pickle.dumps(message)

    def unpickle_message(self, message):
        return pickle.loads(message)
    
if __name__ == '__main__':
    
    if len(sys.argv) != 3:
        print('Usage: python chord_query.py PORT QUERY',
              '\n(the program attempts to query data from an existing chord network where one of the nodes is running at PORT)',
              '\n(QUERY is formed by concatinating PLAYER_ID and YEAR, example tomfarris/25138611948)')
        exit(1)
    
    port_number = (int(sys.argv[1]))
    query = sys.argv[2]
    chord_query = ChordQuery()
    
    print('Querying node with port: ', port_number, ' with key: ', query)
    querying_node = ('localhost', port_number)
    query = ChordQuery.hash_sha1(query) % NODES
    details = chord_query.call_rpc(querying_node, ChordQuery.CHORD_QUERY, [query])
    print('\nQuery Result: ')
    if details:
        print(details)
    else:
        print('Data not found')