#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
@author: Amogha Kagal Jayaprakash

Usage: python chord_populate.py PORT 
(the program attempts to push data from CSV file specified in CSV_FILE_PATH to an existing chord network where one of the nodes is running at PORT)
"""

import csv
import hashlib
import pickle
import socket
import sys
from chord_node import NODES, BUF_SZ

class ChordPopulate(object):
    
    POPULATE_CHORD = 'populate_chord'
    
    def __init__(self):
        self.data = {}
        self.column_names = []
        
    def readFile(self, path):
        with open(path, 'r') as csvFile:
            reader = csv.reader(csvFile)
            header = True
            for row in reader:
                if header is True:
                    self.column_names = row
                    header = False
                else:
                    key = row[0] + row[3]
                    self.data[ChordPopulate.hash_sha1(key) % NODES] = row
        csvFile.close()
    
    @staticmethod
    def hash_sha1(data):
       return int(hashlib.sha1(pickle.dumps(data)).hexdigest(), 16)
   
    def call_rpc(self, destination, method, arguments=[]):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.connect(destination)
                s.sendall(self.pickle_message((method, arguments)))
            except Exception as e:
                print('Failed to connect: ', e)
            finally:
                s.close()
   
    def pickle_message(self, message):
        return pickle.dumps(message)

    def unpickle_message(self, message):
        return pickle.loads(message)
    
if __name__ == '__main__':
    if len(sys.argv) != 3:
        print('Usage: python chord_populate.py PORT CSV_FILE_PATH ',
              '\n(the program attempts to push data from CSV file specified in CSV_FILE_PATH',
              'to an existing chord network where one of the nodes is running at PORT)')
        exit(1)
    
    port_number = (int(sys.argv[1]))
    csv_file_path = sys.argv[2]
    
    chord_populate = ChordPopulate()
    chord_populate.readFile(csv_file_path)
    populating_node = ('localhost', port_number)
    chord_populate.call_rpc(populating_node, ChordPopulate.POPULATE_CHORD, [chord_populate.data])
    print('Chord populate done.')