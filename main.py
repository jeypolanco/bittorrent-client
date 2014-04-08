import argparse
import torrentparser
import hashlib
import requests
from requests import RequestException
from itertools import chain
import bencode
import socket
import struct

class TorrentClient(object):
    def __init__(self, metainfo, tracker_list):
        for tracker in tracker_list:
            try:
                response = self.get_tracker_peerList(tracker, metainfo)
            except RequestException, e:
                continue
        peer_list = self.get_peer_addr_list(response["peers"])
        self.handshake_peer(peer_list, metainfo)

    def handshake_peer(self, peer_list, metainfo):
        bencode_metainfo = metainfo.get_bencode_metainfo()
        for peer in peer_list:
            pipe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            peer_addr = (peer['ip'], peer['port'])
            pipe.settimeout(2.0)
            handshake = self.get_handshake(bencode_metainfo)
            try:
                pipe.connect(peer_addr)
            except socket.timeout:
                print "socket timed out"
      
            pipe.send(handshake)

    def get_handshake(self, metainfo):
        reserved_fmt = 'd'
        reserved = 0

        pstr_fmt = '19s'
        pstr = 'BitTorrent protocol'

        pstrlen_fmt = 'b'
        pstrlen = 19

        peer_id_fmt = '20s'
        peer_id = 'HEOL-123456789012356'

        info_hash_fmt = '20s'
        info_hash = hashlib.sha1(bencode.bencode(metainfo['info'])).digest()

        struct_fmt = pstrlen_fmt + pstr_fmt + reserved_fmt + info_hash_fmt + peer_id_fmt
        handshake = struct.pack(struct_fmt, pstrlen, pstr, reserved, info_hash, peer_id)
        return handshake
    
    def get_tracker_peerList(self, url, metainfo):
        # Params are the parameters required to send a properly formatted
        # request to the tracker
        ## These paramaters are ALL NECESSARY for the tracker to return a peer list.
        params = {
            "info_hash": hashlib.sha1(bencode.bencode(metainfo.metainfo['info'])).digest(),
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
        if metainfo.metainfo['info'].has_key('files'):
            for file in metainfo.metainfo['info']['files']:
                sum += file['length']
        else:
            sum = metainfo.metainfo['info']['length']
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

#class Test(object):
#    arg_parser = argparse.ArgumentParser()
#    arg_parser.add_argument("t_file", help="this is the torrent file we aim to download")
#    args = arg_parser.parse_args()
#    t_parser = TorrentParser(args.t_file)
#    t_client = TorrentClient(t_parser.get_metainfo(), t_parser.get_trackerList())
#

def main():
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument("t_file", help="this is the torrent file we aim to download")
    args = arg_parser.parse_args()
    t_parser = torrentparser.TorrentParser(args.t_file)
    t_client = TorrentClient(t_parser.get_metainfo(), t_parser.get_metainfo().get_trackerList())
    
if __name__ == "__main__":
    main()
