import bencode

class TorrentParser(object):
    def __init__(self, torrent_path):
        with open(torrent_path, 'rb') as inpf:
            self.metainfo = MetaInfo(bencode.bdecode(inpf.read()))
    
    def get_metainfo(self):
        return self.metainfo

class MetaInfo(object):
    def __init__(self, bencoded_metainfo):
        self.metainfo = bencoded_metainfo
    

    def get_bencode_metainfo(self):
        return self.metainfo

    def get_trackerList(self):
        tracker_list = []
        tracker_list.append(self.metainfo['announce'])
        for tracker in self.metainfo['announce-list']:
            tracker_list.append(tracker[0])
        return tracker_list

    def set_trackerList(self, http_tracker_list):
        # Set the value to be type string
        self.metainfo['announce'] = http_tracker_list[0]
        # Set the value to be a list of list
        tracker_list = []
        for tracker in http_tracker_list:
            tracker_list.append([tracker])
        self.metainfo['announce-list'] = tracker_list

