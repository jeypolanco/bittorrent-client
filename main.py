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
    def __init__(self, metainfo, reactor):
        self.reactor = reactor
        self.metainfo = metainfo
        self.peer_list = self.get_peer_list(self.get_tracker_list())
        # The 'pieces' element in the .torrent metafile includes a string of
        # 20-byte hashes, one for each piece in the torrent
        self.num_pieces = len(metainfo['info']['pieces'])/20
        self.missing_pieces = range(self.num_pieces)
        self.connected_peers = {}
        self.connected_peers = self.connect_to_new_peers(self.peer_list, self.connected_peers)
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

    def connect_to_new_peers(self, peer_list, connected_peers):
        for peer_addr in peer_list:
            # Change this back to 25 when you finish debugging
            ## I'm going to assume that a peer will only ever have one port
            ## listening for connections
            if len(connected_peers) < 4 and not connected_peers.has_key(peer_addr['ip']):
                peer = PeerListener(self.reactor, peer_addr, self.metainfo, self)
                if peer.is_connected():
                    connected_peers[peer_addr['ip']] = peer
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
        
    def update_connected_peers_dict(self, connected_peers):
        updated_connected_peers = {}
        for peer_ip in connected_peers:
            if connected_peers[peer_ip].is_connected():
                updated_connected_peers[peer_ip] = connected_peers[peer_ip]
            else:
                continue
        if len(updated_connected_peers) == len(connected_peers):
            pass
        else:
            self.connected_peers = self.connect_to_new_peers(self.peer_list, updated_connected_peers)
            
    def has_missing(self):
        """Returns true if there are pieces missing for assembling the torrent file."""
        self.update_connected_peers_dict(self.connected_peers)
        if len(self.missing_pieces) == 0:
            return False
        else:
            return True
        
    def get_missing(self):
        """Assign a peer to fetch a missing piece"""
        for piece in self.missing_pieces:
            if piece in self.transit:
                continue
            else:
                for peer in self.connected_peers:
                    peer_listener = self.connected_peers[peer]
                    if not peer_listener.getting_piece() and peer_listener.has_piece(piece):
                        peer_listener.get_piece(piece)
                        self.transit.append(piece)

    def set_piece(self, piece, data, peer):
        self.pieces[piece] = data
        self.reset_peer(piece, peer)

    def reset_peer(self, piece, peer):
        """Set peer to a state where it can request a piece"""
        self.transit.remove(piece)
        self.missing_pieces.remove(piece)
        peer.piece_index = None
        
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

class PeerListener(object):
    def __init__(self, reactor, peer_addr, metainfo, piece_assembler):
        self.metainfo = metainfo
        self.choked = True
        self.piece_index = None
        self.pieces_list = None
        self.msg_to_send = ""
        self.msg_recv = ""
        self.block_request_size = 2 ** 14
        self.id_dict = {'bitfield': 5, 'have': 4, 'keep alive': 0, 'unchoke': 1, 'choke': 0, 'piece': 7}
        self.piece_assembler = piece_assembler
        self.reactor = reactor            
        info_hash = hashlib.sha1(bencode.bencode(metainfo['info'])).digest()
        self.sock = socket.socket()
        try:
            self.sock.settimeout(2.0)
            self.sock.connect((peer_addr['ip'], peer_addr['port']))
            self.sock.setblocking(0)
            self.sock.send(self.get_handshake(info_hash))
            self.connected = True
            self.reactor.register_for_read(self)
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

    def on_read(self):
        """Identify whether the data you are reading is a bitfield message or a series of have messages"""
        try:
            output = self.sock.recv(4096)
            if not output:
                self.disconnect()
            else:
                self.parse_message(output)
        except socket.error as err:
            print err
            self.sock.close()

    def parse_message(self, message):
        message = self.msg_recv + message
        while len(message) > 4:
            prefix_length = struct.unpack(">i", message[0:4])[0]
            try:
                message_id = struct.unpack(">b", message[4])[0]
            except IndexError as err:
                print err
            # I'm slicing out the prefix length and message_id byte
            payload = message[5:prefix_length + 5]
            if message[:20] == '\x13BitTorrent protocol':
                # remove the handshake from the message
                message = message[68:]
                self.reactor.register_for_read(self)                
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
                self.reactor.register_for_read(self)
            elif message_id == self.id_dict['have']:
                # If my assumption is wrong I won't be able to get the pieces a
                # peer has in my piece assembler
                index = struct.unpack(">i", payload)[0]
                self.pieces_list[index] = True
                message = message[prefix_length+4:]
                self.reactor.register_for_read(self)                
            elif prefix_length == self.id_dict['keep alive']:
                message = message[4:]
            elif message_id == self.id_dict['unchoke']:
                self.start_requesting_blocks()
                message = message[prefix_length+4:]
            elif message_id == self.id_dict['choke']:
                self.stop_requesting_blocks()
                message = message[prefix_length+4:]
            elif message_id == self.id_dict['piece']:
                print payload
                self.set_block(payload)
                message = message[prefix_length+4:]
            else:
                self.msg_recv = message

    def set_block(self, payload):
        """Save block from peer to a dictionary"""
        index = struct.unpack("!i", payload[0:4])
        if index == self.transit_block['index']:
            begin = self.block_request_size * struct.unpack("!i", payload[4:8])
            if begin == self.transit_block['begin']:
                block_len = len(payload[9:])
                if block_len == self.transit_block['length']:
                    self.block_list[index] = payload[9:]
                    self.piece_blocks[index] = True
        else:
            print "save block problem"
                
    def start_requesting_blocks(self):
        piece_length = self.metainfo['info']['piece length']
        if piece_length % self.block_request_size == 0:
            num_blocks = piece_length / self.block_request_size
            self.piece_blocks = bitstring.BitArray("0b0" * num_blocks)
        else:
            num_blocks = piece_length / self.block_request_size
            self.last_block = piece_length % self.block_request_size
            self.piece_blocks = bitstring.BitArray("0b0" * num_blocks + 1)

    def on_write(self):
        self.msg_to_send += self.generate_msg()
        try:
            sent = self.sock.send(self.msg_to_send)
            self.msg_to_send = self.msg_to_send[sent:]
            if self.msg_to_send:
                self.reactor.register_for_write(self)
                self.reactor.register_for_read(self)
            else:
                self.reactor.register_for_read(self)
                self.msg_to_send = ""
        except socket.error as err:
            print err
            self.sock.close()

    def generate_msg(self):
        if self.choked:
            # unchoke message by sending an interested message
            return '\x00\x00\x00\x01\x02'
        else:
            request_id = struct.pack("b", 6)
            block_index = 0
            for block in self.piece_blocks:
                if not block:
                    block_offset = struct.pack("i", self.block_request_size * block_index)
                    block_index = struct.pack("i", block_index)
                    message_len = struct.pack("i", 13)
                    if piece_blocks[block] == len(piece_blocks) - 1 and self.last_block:
                        block_length = struct.pack("i", self.last_block)
                        return block_length + request_id + block_index + block_offset + message_len
                    else:
                        return block_length + request_id + block_index + block_offset + message_len
                else:
                    keep_alive_msg = "\x00" * 4
                    complete_piece = ""
                    for block in range(len(self.block_list)):
                        complete_piece += self.block_list[block]
                    complete_piece_hash = hashlib.sha1(complete_piece).digest()
                    piece_hash = self.get_piece_hash(self.piece_index)
                    if complete_piece_hash == piece_hash:
                        self.piece_assembler.set_piece(self.piece_index, complete_piece, self)
                        return keep_alive_msg
                    else:
                        self.discard_piece()
                        return keep_alive_msg
                        
    def discard_piece(self):
        self.piece_assembler.reset_peer(self, self.piece_index)
        
    def get_piece_hash(self, piece_index):
        offset = piece_index * 20
        return self.metainfo['info']['pieces'][offset:offset+20]
    
    def get_handshake(self, info_hash):
        pstrlen_pack = struct.pack('b', 19)
        pstr_pack = struct.pack('19s', 'BitTorrent protocol')
        reserved_pack = struct.pack('d', 0)
        info_hash_pack = struct.pack('20s', info_hash)
        peer_id_pack = struct.pack('20s', 'HEOL-123456789012356')
        handshake = pstrlen_pack + pstr_pack + reserved_pack + info_hash_pack + peer_id_pack
        return handshake

    def has_piece(self, piece_ind):
        if self.pieces_list:
            if self.pieces_list[piece_ind]:
                return True
            else:
                return False
        else:
            return False

    def getting_piece(self):
        if self.piece_index == None:
            return False
        else:
            return True
    
    def get_piece(self, piece_ind):
        self.piece_index = piece_ind
        self.reactor.register_for_write(self)

class Reactor(object):                                                        
    def __init__(self):                                                       
        self.want_to_read = []
        self.want_to_write = []
        self.piece_assembler = None

    def set_piece_assembler(self, piece_assembler):
        self.piece_assembler = piece_assembler

    def register_for_read(self, thing):
        self.want_to_read.append(thing)

    def register_for_write(self, thing):
        self.want_to_write.append(thing)

    def loop(self):
        rs, ws, xs = select.select(self.want_to_read, self.want_to_write, [])
        for r in rs:
            self.want_to_read.remove(r)
            r.on_read()
        for w in ws:
            self.want_to_write.remove(w)
            w.on_write()
        if self.piece_assembler.has_missing():
            self.piece_assembler.get_missing()
        else:
            self.piece_assembler.finish()

def main():
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument("t_file", help="this is the torrent file we aim to download")
    args = arg_parser.parse_args()
    with open(args.t_file, 'rb') as inpf:
        metainfo = bencode.bdecode(inpf.read())
    reactor = Reactor()
    piece_assembler = PieceAssembler(metainfo, reactor)
    reactor.set_piece_assembler(piece_assembler)
    while True:
        reactor.loop()
    
if __name__ == "__main__":
    main()
