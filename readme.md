# bittorrent client

A bittorrent client written in python.

# installation requirements

Tested on python 2.7 but also requires:  

    pip install bencode
    pip install requests
    pip install bitstring

# status

-   Currently the bittorrent client is unfinished but it can:
    
    -   connect to the tracker
    
    -   parse the tracker response
    
    -   connect to peers
    
    -   handshake with peers
    
    -   process bitfield, have, choke, unchoke, (not) interested, request and
        piece messages

-   The problem is during the course of downloading a file, I get a bug that
    makes the client stop short of downloading the last couple of pieces of a
    file.
    
    -   I plan on using a network programming framework (twisted) and refactoring
        the code in order to fix this issue.
