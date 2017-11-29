from Crypto.Cipher import AES
from Crypto.PublicKey import RSA 
from Crypto.Util import Counter
from Crypto import Random
from base64 import b64encode, b64decode
from Crypto.PublicKey import RSA 
from Crypto.Signature import PKCS1_v1_5 
from Crypto.Hash import SHA256 
from Crypto.Random.random import getrandbits

import unittest
import datetime 

def GenerateKRandomBits():
	k = 0
	r = None
	while k != 32:
		r = getrandbits( k=32 )
		k = r.bit_length()
	
	print (r.bit_length())
	return bytes( r )

def Encrypt( _buffer, keystring ):
	'''
	Encrypts buffer with keystring (using AES in CBC mode)
	
	Key Arguments:
	_buffer - usually something you want to encrypt (string)
	keystring - 32-bit long key (string)

	Return:
	Encryption of buffer
	'''

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
	return __buffer.decode('utf-8')

def SignSignature( private_key, msg ):
	'''
	Using SHA-256 w/ 32 bit keys.

	Key Arguments:
	private_key - x bits key
	msg - can be a tuple or concatenated msg

	Return:
	encoded64 signed value
	'''

	# import key
	RSAkey = RSA.importKey( private_key )

	# create signer object based off of PKCS V1.5
	signer = PKCS1_v1_5.new( RSAkey )
	
	# create digest object
	h = SHA256.new()
	
	# decode msg data
	signifier, timestamp, pub_key, enc_pw = msg
	signifierStr = str(signifier)
	h.update( b64encode( signifierStr ) )
	h.update( b64encode( timestamp ) )
	h.update( b64encode( pub_key ) )
	h.update( b64encode( enc_pw ) )
	
	# sign the digest
	sign = signer.sign( h )
	
	# return 
	return b64encode( sign )	


def VerifiySignature( public_key, signature, msg ):
	'''
	Verifies with a public key from whom the msg came that it was indeed 
	signed by their private key
	param: public_key_loc Path to public key
	param: signature String signature to be verified
	return: Boolean. True if the signature is valid; False otherwise. 
	'''

	rsakey = RSA.importKey( public_key ) 

	signer = PKCS1_v1_5.new( rsakey ) 

	digest = SHA256.new() 

	signifier, timestamp, pub_key, enc_pw = msg
	signifierStr = str(signifier)
	digest.update( b64encode( signifierStr ) )
	digest.update( b64encode( timestamp ) )
	digest.update( b64encode( pub_key ) )
	digest.update( b64encode( enc_pw ) ) 

	if signer.verify( digest, b64decode( signature ) ):
		return True
	return False

def generate_RSA(bits=2048):
	'''
	Generate an RSA keypair with an exponent of 65537 in PEM format
	param: bits The key length in bits
	Return private key and public key
	'''
	new_key = RSA.generate(bits, e=65537) 
	public_key = new_key.publickey().exportKey("PEM") 
	private_key = new_key.exportKey("PEM") 
	return private_key.decode('utf-8'), public_key.decode('utf-8')

def logInProtocol(login_data):
	timestamp = datetime.datetime.now().strftime("%A, %d. %B %Y %I:%M%p")
	plainPassword = login_data["password"]
	key = GenerateKRandomBits(32)
	encPassword = Encrypt(plainPassword,key)
	sigMsg = timestamp+"|"+login_data["userName"]+"|"+encPassword
	SignSignature( private_key, sigMsg )
	


class TestDigitalSignature( unittest.TestCase ):
	
	def setUp( self ):
		self.private_key, self.public_key = generate_RSA()
		signifier = 1
		timestamp = datetime.datetime.now().strftime("%A, %d. %B %Y %I:%M%p")
		pub_key = self.public_key
		enc_pw = Encrypt( _buffer='skylarlevey', keystring='0123456789abcdefghijklmnopqrstwv' )
		self._msg = ( signifier, timestamp, pub_key, enc_pw )
	
	def testSignMsg( self ):
		_sig = SignSignature( private_key=self.private_key, msg=self._msg  ) 
		self.assertTrue( len(_sig) > 0)
		# print ( _sig )

	def testVerMsg( self ):
		_sig = SignSignature( private_key=self.private_key, msg=self._msg  ) 
		itWorked = VerifiySignature( self.public_key, _sig, self._msg )
		self.assertTrue( itWorked )


class TestKeyPairGeneration( unittest.TestCase ):
	
	def setUp( self ):
		self.private_key, self.public_key = generate_RSA()
	
	def testKeys( self ):
		pass
		# print( self.private_key, "\n\n", self.public_key)
		# print( len ( self.private_key ), "\n\n", len( self.public_key ) )
		# TODO: TEST CASE SHOULD BE ADDED about length 

class TestCryptography( unittest.TestCase ):
	'''
	TestCases for Cryptography Encrypt() and Decrypt() Functions

	Key Arguments:
	unittest.TestCase - inheritance in use
	'''
	
	def setUp( self ):
		self.password = 'skylarlevey'

		self.keystrings = [
			'0123456789abcdefghijklmnopqrstwv', # 32 perfect
		]

		self.g_keystrings = [
			GenerateKRandomBits( ),
			GenerateKRandomBits( ),
			GenerateKRandomBits( )
		]

	def testEncryption( self ):
		ENC = Encrypt( _buffer=self.password, keystring=self.keystrings[0] )		
		self.assertNotEqual( self.password, ENC )

	def testGenEncryption( self ):
		for key in self.g_keystrings:
			print( key )
			ENC = Encrypt( _buffer=self.password, keystring=key)		
			self.assertNotEqual( self.password, ENC )
	
	def testDecryption( self ):
		ENC = Encrypt( _buffer=self.password, keystring=self.keystrings[0] )
		DEC = Decrypt( e_buffer=ENC, keystring=self.keystrings[0] )
		self.assertEqual( self.password, DEC )
	
if __name__ == "__main__":
	unittest.main()
