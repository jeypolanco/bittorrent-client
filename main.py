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
                if peer.sent_handshake:
                    if peer.sent_interested:
                        if peer.getting_piece:
                            if peer.missing_blocks:
                                want_to_write.append(peer)
                            else:
                                self.set_piece(peer.piece_index,
                                               peer.get_assembled_piece(), peer)
                        else:
                            missing_piece = self.get_missing_piece()
                            if peer.has_piece(missing_piece):
                                peer.get_piece(missing_piece)
                                self.transit.append(missing_piece)                                
                    else:
                        want_to_write.append(peer)
                else:
                    want_to_write.append(peer)
            rs, ws, xs = select.select(want_to_read, want_to_write, [])
            # add code that will delete the peer from the connected dict or list
            # if it's timestamp expires
            for r in rs:
                output = r.sock.recv(4096)
                if len(output) == 0:
                    r.sock.close()
                    self.connected_peers.remove(r)
                    self.connected_peers.append(self.connect_to_new_peer(self.peer_list))
                else:
                    r.parse_message(output)
                    r.most_recent_read = int(time.time())
            for w in ws:
                w.generate_msg()

class PeerListener(object):
    def __init__(self, peer_addr, metainfo):

        # Peer state global variables
        self.sent_handshake = False
        self.sent_interested = False
        self.sent_request = False
        
        self.getting_piece = False
        self.getting_block = False
        self.missing_blocks = True
        
        self.received_handshake = False
        self.received_pieces_list = False
        self.received_unchoke = False

        self.metainfo = metainfo
        self.block_request_size = 2 ** 14
        self.block_list, self.last_block_size = self.get_block_list()
        self.transit_block = {}
        
        self.most_recent_read = None
        self.piece_index = None
        self.pieces_list = None
        self.msg_recv = ""
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

    def is_connected(self):
        return self.connected

    def fileno(self):
        return self.sock.fileno()

    def disconnect(self):
        self.connected = False

    def parse_message(self, message):
        message = self.msg_recv + message
        while len(message) > 4:
            prefix_length = struct.unpack(">i", message[0:4])[0]
            message_id = struct.unpack(">b", message[4])[0]
            # I'm slicing out the prefix length and message_id byte
            payload = message[5:prefix_length + 4]
            if self.sent_handshake:
                if message[:20] == '\x13BitTorrent protocol':
                    # remove the handshake from the message
                    message = message[68:]
                    self.received_handshake = True
                elif message_id == self.id_dict['bitfield']:
                    ## Assumption: I'm going to assume that the bitfield message
                    ## will ALWAYS come before a have message and it will only
                    ## arrive ONCE.  This assumption is correct at list in so far
                    ## that the bitfield message will only ever follow a handshake.
                    ## At least in a client that follows specifications.
                    # The following turns the payload into parsable input for the
                    # bitstring.BitArray class to represent the pieces this peer has
                    self.pieces_list = bitstring.BitArray("".join(map(hex, map(ord, payload))))
                    message = message[prefix_length+4:]
                    self.received_pieces_list = True
                elif message_id == self.id_dict['have']:
                    # If my assumption is wrong I won't be able to get the pieces a
                    # peer has in my piece assembler
                    index = struct.unpack(">i", payload)[0]
                    self.pieces_list[index] = True
                    message = message[prefix_length+4:]
                elif prefix_length == self.id_dict['keep alive']:
                    message = message[4:]
                    
                elif self.sent_interested:
                    if message_id == self.id_dict['unchoke']:
                        message = message[prefix_length+4:]
                        self.received_unchoke = True
                        
                    elif self.sent_request:
                        if message_id == self.id_dict['choke']:
                            message = message[prefix_length+4:]
                            self.received_unchoke = False
                            self.sent_interested = False
                        elif message_id == self.id_dict['piece']:
                            print 'foo'
                            self.set_block(payload)
                            print 'world'
                            if '' in self.block_list.viewvalues():
                                pass
                            else:
                                self.missing_blocks = False
                            message = message[prefix_length+4:]

        self.msg_recv = message

    def get_block_list(self):
        """Function returns an empty block list with the index values of each block as a
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
        """Save block from peer to a dictionary"""
        #### Set up your logic for handling pieces here####
        #### Have a variable that stores the blocks in transit ####
        index = struct.unpack("!i", payload[0:4])
        if index == self.transit_block['index']:
            begin = self.block_request_size * struct.unpack("!i", payload[4:8])
            if begin == self.transit_block['begin']:
                block_len = len(payload[9:])
                if block_len == self.transit_block['length']:
                    self.block_list[index] = payload[9:]
                
    def write(self, message):
        # I'm going to assume that my the messages I send will
        # always be small enough to send.  This assumption will be
        # false when you serve files to peers
        try:
            sent = self.sock.send(message)
            if sent == len(message):
                 return True
        except socket.error as err:
            print err

    def generate_msg(self):
        if self.received_handshake:
            if self.received_pieces_list:
                if self.received_unchoke:
                    self.sent_request = self.write(self.get_request_msg())
                else:
                    self.sent_interested = self.write(self.get_interested_msg())
            else:
                # peer is connected and received a hanshake but is waiting
                # for bitfield and have messages
                pass
        else:
             self.sent_handshake = self.write(self.get_handshake_msg())

    def get_interested_msg(self):
        return '\x00\x00\x00\x01\x02'
    
    def get_request_msg(self):
        request_id = struct.pack("b", 6)
        message_len = struct.pack("!i", 13)
        for block_key in self.block_list:
            if self.block_list[block_key] == '':
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

#    def getting_piece(self):
#        if self.piece_index == None:
#            return False
#        else:
#            return True
    
    def get_piece(self, piece_ind):
        self.piece_index = piece_ind
        self.getting_piece = True

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
