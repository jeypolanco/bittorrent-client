import time
import bitstring
import select
import argparse
import hashlib
import requests
from requests import RequestException
import bencode
import socket
import struct
import sys

class PieceAssembler(object):
    """Responsible for assigning peers to fetch missing pieces and assembling
       pieces into the torrent file"""
    def __init__(self, metainfo):
        self.metainfo = metainfo
        self.peer_list = self.get_peer_list(self.get_tracker_list())
        # The 'pieces' element in the .torrent metafile includes a string of
        # 20-byte hashes, one for each piece in the torrent
        self.num_pieces = len(metainfo['info']['pieces'])/20
        self.missing_pieces = range(self.num_pieces)
        self.connected_peers = self.connect_to_peers(self.peer_list)
        # This is a list of pieces that have been assigned to be fetched by a peer
        self.transit = [] 
        # This is a dict with keys corresponding to the index value of a piece
        # and values corresponding to the data sent by a peer
        self.pieces = {}

    def get_tracker_list(self):
        tracker_list = []
        tracker_list.append(self.metainfo['announce'])
        for tracker in self.metainfo['announce-list']:
            tracker_list.append(tracker[0])
        return tracker_list
    
    def get_peer_list(self, tracker_list):
        for tracker in tracker_list:
            # This will return the last tracker in the list to give a valid response
            ## If you would like more peers I suggest to change this method to
            ## allow for multiple tracker
            try:
                response = self.get_tracker_peerList(tracker, self.metainfo)
            except RequestException, e:
                continue
            if response.has_key('failure reason'):
                print response['failure reason']
            else:
                peer_list = self.get_peer_addr_list(response["peers"])
                return peer_list

    def connect_to_peers(self, peer_list):
        connected_peers = []
        for peer_addr in peer_list:
            # Change this back to 25 when you finish debugging
            ## I'm going to assume that a peer will only ever have one port
            ## listening for connections
            if len(connected_peers) < 4:
                peer = PeerListener(peer_addr, self.metainfo)
                if peer.is_connected():
                    print peer.is_connected()
                    connected_peers.append(peer)
                else:
                    continue
        return connected_peers

    def get_tracker_peerList(self, url, metainfo):
        # Params are the parameters required to send a properly formatted
        # request to the tracker
        ## These paramaters are ALL NECESSARY for the tracker to return a peer list.
        params = {
            "info_hash": hashlib.sha1(bencode.bencode(metainfo['info'])).digest(),
            "peer_id": "HEOL-123456789012356",
            "left": self.get_left(metainfo),
            "compact" : 1,
            "downloaded": 0,
            "uploaded" : 0,
            "port" : 10000,
        }
        tracker_connection = requests.get(url, params=params)
        response = tracker_connection.content
        return bencode.bdecode(response)

    def get_left(self, metainfo):
        """ left corresponds to the total length of the file"""
        sum = 0
        # Check if the torrent is one or more files
        if metainfo['info'].has_key('files'):
            for file in metainfo['info']['files']:
                sum += file['length']
        else:
            sum = metainfo['info']['length']
            return sum
        return sum
                
    def get_peer_addr_list(self, response):
        peer_list = []
        peer_dec = map(ord, response)
        for num in range(0, len(response), 6):
            peer_dict = {}
            peer_dict["ip"] = "{0}.{1}.{2}.{3}".format(peer_dec[num], peer_dec[num+1], peer_dec[num+2], peer_dec[num+3])
            peer_dict["port"] = 256 * peer_dec[num+4] + peer_dec[num+5]
            peer_list.append(peer_dict)
        return peer_list
#        decoded_dec_peer = map(ord, response['peers'])
        
    def connect_to_new_peer(self, peer_list):
        for peer_addr in peer_list:
            for peer in self.connected_peers:
                try:
                    sock_addr = peer.sock.getpeername()[0]
                    peer = PeerListener(peer_addr, self.metainfo)
                    if peer.is_connected():
                        return peer
                except socket.error as err:
                    print err
            
#    def has_missing(self):
#        """Returns true if there are pieces missing for assembling the torrent file."""
#        self.update_connected_peers_dict(self.connected_peers)
#        if len(self.missing_pieces) == 0:
#            return False
#        else:
#            return True
        
    def get_missing_piece(self):
        """Return a missing piece not already assigned to a peer"""
        for piece in self.missing_pieces:
            if piece in self.transit:
                continue
            else:
                return piece


    def set_piece(self, piece, data, peer):
        complete_piece_hash = hashlib.sha1(piece).digest()
        piece_hash = peer.get_piece_hash(self.piece_index)
        if complete_piece_hash == piece_hash:
            self.pieces[piece] = data
        self.reset_peer(piece, peer)

    def reset_peer(self, piece, peer):
        """Set peer to a state where it can request a piece"""
        self.transit.remove(piece)
        self.missing_pieces.remove(piece)
        peer.getting_piece = False
        
    def finish(self):
        """Assembles the torrent file and exits the program"""
        if self.metainfo['info'].has_key('files'):
            for ind in range(len(metainfo['info']['files'])):
                file_name = metainfo['info']['files'][ind]['path']
                file_size = metainfo['info']['files'][ind]['length']
                self.create_file(file_name, file_size)
            
        else:
            tmp_buff = ""
            for piece in range(self.num_pieces):
                tmp_buff += pieces[piece]
            file_name = self.metainfo['info']['name']
            with open(file_name, 'wb') as inpf:
                inpf.write(tmp_buff)
        sys.exit()
        
    def create_file(self, file_name, file_size):
        """Create torrent file"""
        data_added = 0
        tmp_buff = ""
        while file_size < data_added and file_size != data_added:
            if len(pieces[piece]) <= file_size - data_added:
                tmp_buff += pieces[piece]
                data_added += len(piece[piece])
            else:
                diff = file_size - data_added
                # slice out the difference between the file_size and data_added
                tmp_buff += pieces[piece][:diff]
                data_added += len(pieces[piece][:diff])
                # assign a new string to the index that corresponds to the string remaining
                pieces[piece] = pieces[piece][diff:]
        with open(file_name, 'wb') as inpf:
            inpf.write(tmp_buff)

    def loop(self):
#        while True:
            want_to_read = []
            want_to_write = []
            for peer in self.connected_peers:
                want_to_read.append(peer)
                if peer.state['sent interested']:
                    if peer.state['getting piece']:
                        if peer.state['missing blocks']:
                            want_to_write.append(peer)
                        else:
                            self.set_piece(peer.piece_index,
                                           peer.get_assembled_piece(), peer)
                    else:
                        if peer.state['received pieces list']:
                            missing_piece = self.get_missing_piece()
                            if peer.has_piece(missing_piece):
                                peer.get_piece(missing_piece)
                                self.transit.append(missing_piece)                                
                else:
                    want_to_write.append(peer)
            rs, ws, xs = select.select(want_to_read, want_to_write, [])
            # add code that will delete the peer from the connected dict or list
            # if it's timestamp expires
            for r in rs:
                output = r.sock.recv(2**14)
                if len(output) == 0:
                    r.sock.close()
                    self.connected_peers.remove(r)
                    self.connected_peers.append(self.connect_to_new_peer(self.peer_list))
                else:
                    r.append_to_msg_stream(output)                    
                    raw_message = r.get_full_raw_message(r.get_message_stream())
                    while raw_message:
                        r.set_state(r.parse_raw_message(raw_message))
                        r.slice_message_from_stream(len(raw_message))
                        raw_message = r.get_full_raw_message(r.get_message_stream())
#                    r.set_state(r.parse_messages(output))
                    r.most_recent_read = int(time.time())
            for w in ws:
                w.set_state(w.generate_msg())

class PeerListener(object):
    def __init__(self, peer_addr, metainfo):

        # Peer state global variables
        self.state = {'sent handshake': False, 'sent interested': False, 'sent request': False,
                      'getting piece': False, 'getting block': False, 'missing blocks': True,
                      'received handshake': False, 'received pieces list': False, 'received unchoke': False}
        self.metainfo = metainfo
        self.block_request_size = 2 ** 14
        self.block_list, self.last_block_size = self.get_block_list()
        self.transit_block = {}
        
        self.most_recent_read = None
        self.piece_index = None
        self.pieces_list = None
        self.message_stream = ""
        self.id_dict = {'bitfield': 5, 'have': 4, 'keep alive': 0, 'unchoke': 1, 'choke': 0, 'piece': 7}
        self.info_hash = hashlib.sha1(bencode.bencode(metainfo['info'])).digest()
        
        self.sock = socket.socket()
        try:
            self.sock.settimeout(2.0)
            self.sock.connect((peer_addr['ip'], peer_addr['port']))
            self.sock.setblocking(0)
            self.connected = True
        except socket.error as err:
            print err
            self.sock.close()
            self.connected = False

    def append_to_msg_stream(self, stream):
        self.message_stream += stream

    def slice_message_from_stream(self, message_len):
        self.message_stream = self.message_stream[message_len:]
        
    def is_connected(self):
        return self.connected

    def fileno(self):
        return self.sock.fileno()

    def get_state(self):
        """Returns a dictionary consisting of variables that define the state of the peer"""
        return self.state

    def get_message_stream(self):
        return self.message_stream
    
    def get_full_raw_message(self, message_stream):
        """Method will return a message """
        message = ''
        if message_stream[:20] == '\x13BitTorrent protocol':
            message = message_stream[0:68]
        else:
            if len(message_stream) >= 5:
                prefix_len = struct.unpack(">i", message_stream[0:4])[0]
                raw_payload = message_stream[4:prefix_len + 4]
                if len(raw_payload) == prefix_len:
                    message = message_stream[0:prefix_len+4]
        return message

    def parse_raw_message(self, message):
        message_dict = {'sent': '', 'incomplete': ''}
        if message[:20] == '\x13BitTorrent protocol':        
            message_dict['message id'] = 'handshake'
            message_dict['payload'] =  message[0:68]

        else:
            message_dict['prefix length'] = struct.unpack(">i", message[0:4])[0]            
            raw_payload = message[4:message_dict['prefix length'] + 4]
            message_dict['message id'] = struct.unpack(">b", message[4])[0]
            message_dict['payload'] = self.parse_payload(raw_payload)
        return message_dict

#    def parse_messages(self, raw_message):
#        message_list = []
#        last_complete_message = True
#        while last_complete_message and len(raw_message) > 4:
#            message_dict = {'sent': '', 'incomplete': ''}
#            # This is only necessary because I want the method that I use to set
#            # the state of the peer to take messages that have both been sent
#            # and received.
#            message_dict['prefix length'] = struct.unpack(">i", raw_message[0:4])[0]
#            raw_payload = raw_message[4:message_dict['prefix length'] + 4]
##            # keep-alive message
##            if message_dict['prefix length'] == 0:
##                message_dict['message id'] = message_dict['prefix length']
##                next_msg_offset = message_dict['prefix length'] + 4
##                raw_message = raw_message[next_msg_offset:]
##                message_list.append(message_dict)
#            # handshake response
#            if raw_message[:20] == '\x13BitTorrent protocol':
#                message_dict['message id'] = 'handshake'
#                message_dict['payload'] =  raw_message[0:68]
#                raw_message = raw_message[68:]
#                message_list.append(message_dict)
#            # all other bt protocol messages
#            elif len(raw_payload) == message_dict['prefix length']:
#                message_dict['message id'] = struct.unpack(">b", raw_message[4])[0]
#                message_dict['payload'] = self.parse_payload(raw_payload)
#                message_list.append(message_dict)
#                next_msg_offset = message_dict['prefix length'] + 4
#                raw_message = raw_message[next_msg_offset:]                    
#            else:
#                # I need to save the incomplete message and add it to the raw
#                # message for the next time this method is called
#                message_dict['incomplete'] = raw_message
#                message_list.append(message_dict)
#                last_complete_message = False
#        return message_list

    def parse_payload(self, raw_payload):
        payload_dict = {}
        message_id = struct.unpack('!b', raw_payload[0])[0]
        if self.id_dict['bitfield'] == message_id:
            payload_dict['bitfield'] = bitstring.BitArray("".join(map(hex, map(ord, raw_payload[1:]))))
        elif self.id_dict['have'] == message_id:
            payload_dict['piece index'] = raw_payload[1:]
        elif self.id_dict['piece'] == message_id:
            payload_dict['index'] = raw_payload[1:5]
            payload_dict['begin'] = raw_payload[5:9]
            payload_dict['block'] = raw_payload[9:]
        return payload_dict

    def set_state(self, message_dict):
        """Method takes a list of messages read or written by the peer and uses the
        message id to set the state.  It returns a list of all states matched"""
#        state_match_list = []
#        for message in message_list:
        if message_dict['sent'] == 'request':
            self.state['sent request'] = True
            return message_dict['sent']
        elif message_dict['sent'] == 'interested':
            self.state['sent interested'] = True
            return message_dict['sent']
        elif message_dict['sent'] == 'handshake':
            self.state['sent handshake'] = True
            return message_dict['sent']
        elif message_dict['message id'] == 'handshake':
            self.state['received handshake'] = True
            return message_dict['message id']
        elif message_dict['message id'] == self.id_dict['bitfield']:
            self.pieces_list = message_dict['payload']['bitfield']
            self.state['received pieces list'] = True
            return message_dict['message id']
        elif message_dict['message id'] == self.id_dict['have']:
            index = struct.unpack('!i', message_dict['payload']['piece index'])[0]
            self.pieces_list[index] = True
            return message_dict['message id']
        elif message_dict['prefix length'] == self.id_dict['keep alive']:
            return message_dict['prefix length']
        elif message_dict['message id'] == self.id_dict['unchoke']:
            self.state['received unchoke'] = True
            return message_dict['message id']
        elif message_dict['message id'] == self.id_dict['choke']:
            self.state['received unchoke'] = False
            self.state['sent interested'] = False
            return message_dict['message id']
        elif message_dict['message id'] == self.id_dict['piece']:
            self.set_block(message_dict['payload'])
            return message_dict['message id']
        else:
            return 'no state change'

    def get_block_list(self):
        """Method returns an empty block list with the index values of each block as a
        key to the dict and number remainder that let's us now if the last block
        is smaller than all the other blocks we request.

        """
        piece_length = self.metainfo['info']['piece length']
        num_blocks = piece_length / self.block_request_size
        remainder = piece_length % self.block_request_size
        block_dict = {}
        for index in range(num_blocks):
            # If the piece_length is not evenly divisible by the block_request_size
            # add 1 (to account for the remainder) to the block_list
            if not remainder == 0:
                if index == num_blocks -1:
                    block_dict[index] = ''
                    block_dict[index+1] = ''
            else:
                block_dict[index] = ''
        return block_dict, remainder

        
    def set_block(self, payload):
        """Save block from peer to a dictionary and return the index value of the block"""
        #### Set up your logic for handling pieces here####
        #### Have a variable that stores the blocks in transit ####
        if payload['index'] == self.transit_block['index']:
            begin = struct.unpack("!i", payload['begin'])[0]
            begin_index = begin / self.block_request_size
            if payload['begin'] == self.transit_block['begin']:
                block_len = len(payload['block'])
                if block_len == struct.unpack("!i", self.transit_block['length'])[0]:
                    self.block_list[begin_index] = payload['block']
                    return begin_index
        return -1
                
    def write(self, message):
        try:
            sent = self.sock.send(message)
            return sent
        except socket.error as err:
            print err
            return 0

    def generate_msg(self):
        """Method sends a single message according to the state of the peer and returns
        a dict with the value of the sent message

        """
        message = {'sent': '', 'message id': '', 'payload': '', 'prefix length': '', 'incomplete': ''}
        if self.state['received handshake']:
            if self.state['received pieces list']:
                if self.state['received unchoke']:
                    ###### rewrite this so that it can send multiple request but
                    ###### limit the number of request
                    msg = self.get_request_msg()
                    sent_len = self.write(msg)
                    if len(msg) == sent_len:
                        message['sent'] = 'request'
                else:
                    if not self.state['sent interested']:
                        msg = self.get_interested_msg()
                        sent_len = self.write(msg)
                        if len(msg) == sent_len:
                            message['sent'] = 'interested'                    
            else:
                # peer is connected and received a hanshake but is waiting
                # for bitfield and have messages
                message['sent'] = ''
        else:
            if not self.state['sent handshake']:
                msg = self.get_handshake_msg()
                sent_len = self.write(msg)
                if len(msg) == sent_len:
                    message['sent'] = 'handshake'
        return message

    def get_interested_msg(self):
        return '\x00\x00\x00\x01\x02'
    
    def get_request_msg(self):
        #### Fix this so that you dont make multiple request of the same offset
        request_id = struct.pack("b", 6)
        message_len = struct.pack("!i", 13)
        for block_key in self.block_list:
            if self.block_list[block_key] == '':
                ##### If I make the block list have the transit block dict as a
                ##### key I can make multiple request and check the validaty
                self.transit_block['begin'] = struct.pack("!i", self.block_request_size * block_key)
                self.transit_block['index'] = struct.pack("!i", self.piece_index)
                if block_key == len(self.block_list) - 1 and self.last_block > 0:
                    self.transit_block['length'] = struct.pack("!i", self.last_block)
                    message = message_len + request_id + self.transit_block['index'] + \
                              self.transit_block['begin'] + self.transit_block['length']
                    return message
                else:
                    self.transit_block['length'] = struct.pack("!i", self.block_request_size)
                    message = message_len + request_id + self.transit_block['index'] + \
                              self.transit_block['begin'] + self.transit_block['length']                    
                    return message

    def get_assembled_piece(self):
        complete_piece = ""
        for block in self.block_list:
            complete_piece += self.block_list[block]
        return complete_piece
                
    def get_handshake_msg(self):
        pstrlen_pack = struct.pack('b', 19)
        pstr_pack = struct.pack('19s', 'BitTorrent protocol')
        reserved_pack = struct.pack('d', 0)
        info_hash_pack = struct.pack('20s', self.info_hash)
        peer_id_pack = struct.pack('20s', 'HEOL-123456789012356')
        handshake = pstrlen_pack + pstr_pack + reserved_pack + info_hash_pack + peer_id_pack
        return handshake
                        
    def discard_piece(self):
        self.piece_assembler.reset_peer(self, self.piece_index)
        
    def get_piece_hash(self, piece_index):
        offset = piece_index * 20
        return self.metainfo['info']['pieces'][offset:offset+20]

    def has_piece(self, piece_ind):
        if self.pieces_list[piece_ind]:
            return True
        else:
            return False

    def get_piece(self, piece_ind):
        self.piece_index = piece_ind
        self.state['getting piece'] = True

def main():
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument("t_file", help="this is the torrent file we aim to download")
    args = arg_parser.parse_args()
    with open(args.t_file, 'rb') as inpf:
        metainfo = bencode.bdecode(inpf.read())
    piece_assembler = PieceAssembler(metainfo)
    piece_assembler.loop()
    
if __name__ == "__main__":
    main()
