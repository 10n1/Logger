# websocket_test.py

import hashlib
import base64
import getopt
import sys

def Main( ):
	opts, args = getopt.getopt( sys.argv[1:], '' );

	websocketGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	websocketkey = args[0] # "T4rzylzMKeDpchXJJv1KSg=="

	m = hashlib.new( 'sha1' )
	m.update( websocketkey + websocketGUID )
	
	sha1Hash = m.digest()
	base64Encoded = base64.encodestring( sha1Hash )

	print '''
	Sec-WebSocket-Key: {0:25}
	SHA1: {1:25}
	Sec-WebSocket-Accept: {2:25}'''.format( websocketkey, sha1Hash, base64Encoded )


if __name__ == "__main__":
	Main()
