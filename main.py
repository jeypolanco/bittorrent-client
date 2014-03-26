import argparse
import torrentparser
import hashlib
import requests
from requests import RequestException
from itertools import chain
import bencode

class TorrentClient(object):
    def __init__(self, metainfo, tracker_list):
        for tracker in tracker_list:
            try:
                response = self.get_tracker_peerList(tracker, metainfo)
            except RequestException, e:
                continue
        peer_list = self.get_peer_addr(response["peers"])
        print peer_list

    def get_tracker_peerList(self, url, metainfo):
        # Params are the parameters required to send a properly formatted
        # request to the tracker

        params = {
            "info_hash": hashlib.sha1(bencode.bencode(metainfo.metainfo['info'])).digest(),
            "peer_id": "HEOL-123456789012356",
            "left": self.get_left(metainfo),
        }
        tracker_connection = requests.get(url, params=params)
        print tracker_connection.url
        response = tracker_connection.content
        return bencode.bdecode(response)

    def get_left(self, metainfo):
        """ left corresponsds to the total length of the file"""
        sum = 0
        # Check if the torrent is one or more files
        if metainfo.metainfo['info'].has_key('files'):
            for file in metainfo.metainfo['info']['files']:
                sum += file['length']
        else:
            sum = metainfo.metainfo['info']['length']
            return sum
        return sum
                
    def get_peer_addr(self, response):
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
