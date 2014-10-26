import logging
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
        self.peer_list = self.get_peer_list(self.get_tracker_list(metainfo))
        # The 'pieces' element in the .torrent metafile includes a string of
        # 20-byte hashes, one for each piece in the torrent
        self.num_pieces = len(metainfo['info']['pieces'])/20
        self.missing_pieces = range(self.num_pieces)
        if not self.peer_list == -1:
            self.connected_peers = self.connect_to_peers(self.peer_list)
        # This is a dict with keys corresponding to the index value of a piece
        # and values corresponding to the data sent by a peer
        self.pieces = {}

    def get_tracker_list(self, metainfo):
        tracker_list = []
        if 'http' in metainfo['announce']:
            tracker_list.append(metainfo['announce'])
        for tracker in metainfo.get('announce-list', []):
            if 'http' in tracker[0]:
                tracker_list.append(tracker[0])
        return tracker_list
    
    def get_peer_list(self, tracker_list):
        peer_str_response = ''
        for tracker in tracker_list:
            # This will return the last tracker in the list to give a valid response
            ## If you would like more peers I suggest to change this method to
            ## allow for multiple tracker
            response = self.get_tracker_peerList(tracker, self.metainfo)
            if type(response) == dict:
                if response.has_key('failure reason'):
                    print response['failure reason']
                elif response.has_key('peers'):
                    peer_str_response += response['peers']
        if len(peer_str_response) == 0:
            return -1
        else:
            peer_list = self.get_peer_addr_list(peer_str_response)
            return peer_list
        
    def get_peer_addr_list(self, response):
        peer_list = []
        peer_dec = map(ord, response)
        for num in range(0, len(response), 6):
            peer_dict = {}
            peer_dict["ip"] = "{0}.{1}.{2}.{3}".format(peer_dec[num], peer_dec[num+1], peer_dec[num+2], peer_dec[num+3])
            peer_dict["port"] = 256 * peer_dec[num+4] + peer_dec[num+5]
            peer_list.append(peer_dict)
        return peer_list

    def connect_to_peers(self, peer_list):
        connected_peers = []
        connected_addr = set()
        for peer_addr in peer_list:
            # Change this back to 25 when you finish debugging
            ## I'm going to assume that a peer will only ever have one port
            ## listening for connections
            if len(connected_peers) < 2 and peer_addr['ip'] not in connected_addr:
                peer = PeerListener(peer_addr, self.metainfo)
                if peer.is_connected():
                    print peer.is_connected()
                    connected_peers.append(peer)
                    connected_addr.add(peer_addr['ip'])
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
        try:
            tracker_connection = requests.get(url, params=params, timeout=2.0)
            tracker_response = tracker_connection.content
            if tracker_response == None:
                raise Exception("The tracker is returning nothing!")
            assert len(tracker_response) != 0
            bresponse = bencode.bdecode(tracker_response)
            return bresponse
        except requests.exceptions.Timeout as err:
            print err

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
        
    def connect_to_new_peer(self, peer_list):
        for peer_addr in peer_list:
            if len(self.connected_peers) == 0:
                peer = PeerListener(peer_addr, self.metainfo)
                if peer.is_connected():
                    return peer
            else:
                for peer in self.connected_peers:
                    try:
                        sock_addr = peer.sock.getpeername()[0]
                        if peer_naddr != sock_addr:
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
            return piece

    def reset_peer(self, piece, peer):
        """Set peer to a state where it can request a piece"""
        self.missing_pieces.remove(piece)
        
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

    def replace(self, peer):
        peer.sock.close()
        print self.connected_peers
        print self.peer_list
        self.connected_peers.remove(peer)
        new_peer = self.connect_to_new_peer(self.peer_list)
        self.connected_peers.append(new_peer)
        print self.connected_peers
        return new_peer

    def peer_in_read_state(self, peer):
        """Peer will always be in a read state unless it's finished assembling all it's
        blocks"""
        if peer.state['missing block']:
            return True

    def peer_in_write_state(self, peer):
        if peer.state['sent interested']:
            if peer.state['getting piece']:
                if peer.state['missing blocks']:
                    return True

    def peer_is_finished(self, peer):
        if not peer.state['missing block']:
            return True

    def loop(self):
        while True:
            time.sleep(5)
            want_to_read = []
            want_to_write = []
            for peer in self.connected_peers:
                # After a peer has a complete piece
                want_to_read.append(peer)
                if peer.state['sent interested']:
                    if peer.state['getting piece']:
                        if peer.state['missing blocks']:
                            if len(self.pieces) == self.num_pieces:
                                self.finish()
                            else:
                                want_to_write.append(peer)
                        else:
                            piece = peer.get_assembled_piece()
                            self.pieces[peer.piece_index] = piece
                            self.missing_pieces.remove(peer.piece_index)
                            want_to_read.remove(peer)
                            want_to_write.append(peer)
                    else:
                        if peer.state['received pieces list']:
                            missing_piece = self.get_missing_piece()
                            if peer.has_piece(missing_piece):
                                peer.get_piece(missing_piece)
                else:
                    want_to_write.append(peer)

            rs, ws, xs = select.select(want_to_read, want_to_write, [])
            # add code that will delete the peer from the connected dict or list
            # if it's timestamp expires
            for r in rs:
                output = r.sock.recv(2**14)
                if len(output) == 0:
                    self.replace(peer)
                else:
                    r.append_to_msg_stream(output)                    
                    raw_message = r.get_full_raw_message(r.get_message_stream())
                    while raw_message:
                        r.set_state(r.parse_raw_message(raw_message))
                        r.slice_message_from_stream(len(raw_message))
                        raw_message = r.get_full_raw_message(r.get_message_stream())
                    r.most_recent_read = int(time.time())
            for w in ws:
                w.set_state(w.send_msg())

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
        num_pieces = len(self.metainfo['info']['pieces'])/20
        self.pieces_list = bitstring.BitArray(length=self.get_valid_bitarray_len(num_pieces))
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

    def get_valid_bitarray_len(self, num_pieces):
        bitfield_byte_num = num_pieces / 8
        remainder = num_pieces % 8
        if remainder != 0:
            return 8 * (bitfield_byte_num + 1)
        else:
            return 8 * bitfield_byte_num
        
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
            if message_dict['prefix length'] == 0:
                message_dict['message id'] = 'keep alive'
            else:
                raw_payload = message[4:message_dict['prefix length'] + 4]
                message_dict['message id'] = struct.unpack(">b", message[4])[0]
                message_dict['payload'] = self.parse_payload(raw_payload)
        return message_dict

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
            self.state['received pieces list'] = self.set_pieces_list(message_dict['payload']['bitfield'])
            return message_dict['message id']
        elif message_dict['message id'] == self.id_dict['have']:
            index = struct.unpack('!i', message_dict['payload']['piece index'])[0]
            self.state['received pieces list'] = self.set_pieces_list(index)
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
        elif message_dict['message id'] == 'have all blocks':
            self.state['missing blocks'] = False
        else:
            return 'no state change'

    def set_pieces_list(self, value):
        """Assign the pieces that a peer has to the pieces_list data structure"""
        if type(value) == int:
            self.pieces_list[value] = True
        else:
            for piece in range(len(value)):
                self.pieces_list[piece] = value[piece]
        return True

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
        return (block_dict, remainder)

        
    def set_block(self, payload):
        """Save block from peer to a dictionary and return the index value of the block"""
        #### Set up your logic for handling pieces here####
        #### Have a variable that stores the blocks in transit ####
        begin = struct.unpack("!i", payload['begin'])[0]
        begin_index = begin / self.block_request_size
        transit_block = self.block_list[begin_index]
        if payload['index'] == transit_block['index']:
            if payload['begin'] == transit_block['begin']:
                block_len = len(payload['block'])
                if block_len == struct.unpack("!i", transit_block['length'])[0]:
                    self.block_list[begin_index] = payload['block']
                    index = struct.unpack("!i", payload['index'])[0]
                    assert type(index) == int
                    return begin_index
        return -1
                
    def write(self, message):
        try:
            sent = self.sock.send(message)
            return sent
        except socket.error as err:
            print err
            return 0

    def have_all_blocks(self):
        for key in self.block_list:
            if type(self.block_list[key]) == dict or self.block_list[key] == '':
                return False
            else:
                return True

    def check_hash_piece(self):
        piece = reduce(lambda a,z: a+self.block_list[z], self.block_list.keys(), '')
        peer_piece_hash = hashlib.sha1(piece).digest()
        begin_slice = self.piece_index * 20
        end_slice = begin_slice + 20
        metainfo_piece_hash = self.metainfo['info']['pieces'][begin_slice:end_slice]
        print peer_piece_hash
        print metainfo_piece_hash
        if peer_piece_hash == metainfo_piece_hash:
            return True
        else:
            return False
            
    def send_msg(self):
        """Method sends a single message according to the state of the peer and returns
        a dict with the value of the sent message

        """
        message = {'sent': '', 'message id': '', 'payload': '', 'prefix length': '', 'incomplete': ''}
        if self.state['received handshake']:
            if self.state['received pieces list']:
                if self.state['received unchoke']:
                    # if the len of message is zero then either we have a
                    # pending request or we have all block.  How can we tell
                    # which is it?  If we have no dict values in the block_list.
                    if self.have_all_blocks() and self.check_hash_piece():
                        message['message id'] = 'have all blocks'
                    else:
                        request_msg = self.get_request_msg()
                        sent_len = self.write(request_msg)
                        if len(request_msg) == sent_len:
                            message['sent'] = 'request'
                else:
                    if not self.state['sent interested']:
                        interested_msg = self.get_interested_msg()
                        sent_len = self.write(interested_msg)
                        if len(interested_msg) == sent_len:
                            message['sent'] = 'interested'                    
            else:
                # peer is connected and received a hanshake but is waiting
                # for bitfield and have messages
                message['sent'] = ''
        else:
            if not self.state['sent handshake']:
                handshake_msg = self.get_handshake_msg()
                sent_len = self.write(handshake_msg)
                if len(handshake_msg) == sent_len:
                    message['sent'] = 'handshake'
        return message

    def get_interested_msg(self):
        return '\x00\x00\x00\x01\x02'
    
    def get_request_msg(self):
        # What will this program do if I try to get a request msg with one
        # already in transit?  It will return an empty string.  I need to take
        # into account the possibility that I may have requested a piece but
        # have not receieved it yet.
        ## Do nothing.
        request_id = struct.pack("b", 6)
        message_len = struct.pack("!i", 13)
        transit_block = {}
        message = ''
        for block_key in self.block_list:
            # If the requested block has not been returned in under 20 seconds
            # or the block hasn't been requested issue the request
            print self.block_list
            if self.block_list[block_key] == '' or (self.block_list[block_key]['time'] - time.time()) > 20:
                transit_block['begin'] = struct.pack("!i", self.block_request_size * block_key)
                transit_block['index'] = struct.pack("!i", self.piece_index)
                transit_block['time'] = time.time()
                # This handles the case where the last block is smaller than the other requested block
                if block_key == len(self.block_list) - 1 and self.last_block_size > 0:
                    transit_block['length'] = struct.pack("!i", self.last_block_size)
                    message = message_len + request_id + transit_block['index'] + \
                              transit_block['begin'] + transit_block['length']
                else:
                    transit_block['length'] = struct.pack("!i", self.block_request_size)
                    message = message_len + request_id + transit_block['index'] + \
                              transit_block['begin'] + transit_block['length']
                self.block_list[block_key] = transit_block
        return message

    def get_assembled_piece(self):
        complete_piece = ""
        for block in self.block_list:
            complete_piece += self.block_list[block]
        self.reset_peer()
        return complete_piece


    def reset_peer(self):
        self.state = {'sent handshake': True, 'sent interested': True, 'sent request': False,
                      'getting piece': False, 'getting block': False, 'missing blocks': True,
                      'received handshake': False, 'received pieces list': True, 'received unchoke': True}
        self.block_list, self.last_block_size = self.get_block_list()
        self.transit_block = {}
        self.most_recent_read = None
        
    def get_handshake_msg(self):
        pstrlen_pack = struct.pack('b', 19)
        pstr_pack = struct.pack('19s', 'BitTorrent protocol')
        reserved_pack = struct.pack('d', 0)
        info_hash_pack = struct.pack('20s', self.info_hash)
        peer_id_pack = struct.pack('20s', 'HEOL-123456789012356')
        handshake = pstrlen_pack + pstr_pack + reserved_pack + info_hash_pack + peer_id_pack
        return handshake
                        
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
    logging.basicConfig(filename='bt.log', level=logging.DEBUG)    
    with open(args.t_file, 'rb') as inpf:
        metainfo = bencode.bdecode(inpf.read())
    piece_assembler = PieceAssembler(metainfo)
    if piece_assembler.peer_list == -1:
        print "torrent has no peers"
        return -1
    else:
        piece_assembler.loop()
    
if __name__ == "__main__":
    main()
