from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto import Random
from base64 import b64encode, b64decode

def Encrypt( _buffer, keystring ):
	'''
	Encrypts buffer with keystring (using AES in CBC mode)
	
	Key Arguments:
	_buffer - usually something you want to encrypt (string)
	keystring - 32-bit long key (string)

	Return:
	Encryption of buffer
	'''

	# TODO: EDGE CASE: buffer... format??? I think it's just a password
	# TODO: EDGE CASE: keystring... at least 32 bits restriction

	# TLS style padding
	plength = AES.block_size - ( len (_buffer) )% AES.block_size;
	_buffer += chr( plength ) * plength;

	# generate inital vector as a random value using PRNG
	iv = Random.new().read(AES.block_size);
	
	# create AES cipher object
	cipher = AES.new(keystring, AES.MODE_CBC, iv);

	# encrypt the buffer
	e_buffer = b64encode( iv + cipher.encrypt(_buffer) )

	# return e_buffer
	return e_buffer

def Decrypt( e_buffer, keystring ):
	'''
	Decrypts the e_buffer with keystring (using AES in CBC mode)

	Key Arguments:
	e_buffer - usually something you want to decrypt (string)
	keystring - 32-bit long key (string)

	Return:
	Decryption of e_buffer

	'''
	
	# TODO: EDGE CASE: buffer... format??? I think it's just a password
	# TODO: EDGE CASE: keystring... at least 32 bits restriction

	# read in encrypted payload
	e_buffer = b64decode(e_buffer)

	# initialize intiial vector slice of block size
	iv = e_buffer[:AES.block_size]
	e_buffer = e_buffer[AES.block_size:]

	# create AES cipher object
	cipher = AES.new(keystring, AES.MODE_CBC, iv)

	# decrypted the encrypted buffer
	_buffer = cipher.decrypt( e_buffer )
	
	# remove TLS padding
	__buffer = _buffer[:len(_buffer)-ord(_buffer[-1])]
	
	# return __buffer
	return __buffer


if __name__ == "__main__":
	
	keystring = '0123456789abcdefghijklmnopqrstwv'
	password = 'skylarlevey'
	
	ENC = Encrypt( _buffer=password, keystring=keystring )
	DEC = Decrypt( e_buffer=ENC, keystring=keystring )
	
	print( "[ENC]=%s\n[DEC]%s\n" % (ENC,DEC) )