from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto import Random
from base64 import b64encode, b64decode
from Crypto.PublicKey import RSA 
from Crypto.Signature import PKCS1_v1_5 
from Crypto.Hash import SHA256 
from Crypto.Random.random import getrandbits

import unittest
import datetime 
import os

def Generate32BitKey():
	return os.urandom(32);

def Encrypt( _buffer, keystring ):
	'''
	Encrypts buffer with keystring (using AES in CBC mode)
	
	Key Arguments:
	_buffer - usually something you want to encrypt (string)
	keystring - 32-bit long key (string)

	Return:
	Encryption of buffer
	'''

	if len(keystring) == 32:
		pass
	else:
		raise KeyError('keystring argument must be 32 bytes.')

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
	
	if len(keystring) == 32:
		pass
	else:
		raise KeyError('keystring argument must be 32 bytes.')

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

def SignWithPrivateKey( private_key, msg ):
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
	h = SHA256.new(msg)
	
	# sign the digest
	signature = signer.sign( h )
	
	# return 
	return b64encode(sign)


def VerifiySignedWithPublicKey( public_key, signature, msg ):
	'''
	Verifies with a public key from whom the msg came that it was indeed 
	signed by their private key
	param: public_key_loc Path to public key
	param: signature String signature to be verified
	return: Boolean. True if the signature is valid; False otherwise. 
	'''

	pubKey = RSA.importKey( public_key ) 
	signer = PKCS1_v1_5.new( pubKey ) 

	digest = SHA256.new(msg) 

	if signer.verify( digest, b64decode(signature)  ):
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

class TestDigitalSignature( unittest.TestCase ):
	
	def setUp( self ):

		# user credentials	
		username='skylar-qwerty'
		password='skylarlevy'
		
		self.private_key, self.public_key = generate_RSA()
		timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
		pub_key = self.public_key
		enc_pw = Encrypt( _buffer=password, keystring=Generate32BitKey() )
		self._msg = timestamp+username+enc_pw
	
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
		self.assertTrue( self.private_key != None and self.public_key != None )

class TestRandomKeyGeneration( unittest.TestCase ):
	
	def testKey( self ):
		key = Generate32BitKey()
		self.assertTrue( len( key ) == 32 )
	
	def testMultipleKey( self ):
		keys = [
			Generate32BitKey(),
			Generate32BitKey(),
			Generate32BitKey(),
			Generate32BitKey(),
			Generate32BitKey()
		]
		
		for key in keys:
			self.assertTrue( len( key ) == 32 )

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
			'0123456789abcdefghijklmnopqrstw', # 31 perfect-1
			'0123456789abcdefghijklmnopqrstwvx' # 34 perfect+1	
		]

		self.gen_ks = [
			Generate32BitKey(),
			Generate32BitKey(),
			Generate32BitKey(),
		]

	def testEncryption( self ):
		ENC = Encrypt( _buffer=self.password, keystring=self.keystrings[0] )		
		self.assertNotEqual( self.password, ENC )
	
	def testDecryption( self ):
		ENC = Encrypt( _buffer=self.password, keystring=self.keystrings[0] )
		DEC = Decrypt( e_buffer=ENC, keystring=self.keystrings[0] )
		self.assertEqual( self.password, DEC )
	
	def testEncryption_non_32_bit_key( self ):
		self.assertRaises( KeyError, Encrypt, self.password, self.keystrings[1] )
		self.assertRaises( KeyError, Encrypt, self.password, self.keystrings[2] )
	
	def testDecryption_non_32_bit_key( self ):
		
		## 32 bit key
		ENC = Encrypt( _buffer=self.password, keystring=self.keystrings[0] )
		## 31 bit key
		self.assertRaises( KeyError, Decrypt, e_buffer=ENC, keystring=self.keystrings[1] )
	
	def testGeneratedEncryption( self ):
		'''generates 44-bit keys out of the password'''
		for key in self.gen_ks:
			ENC = Encrypt( _buffer=self.password, keystring=key )
			self.assertNotEqual( self.password, ENC )
	
	def testGeneratedDecryption( self ): 
		for key in self.gen_ks:
			ENC = Encrypt( _buffer=self.password, keystring=key )
			DEC = Decrypt( e_buffer=ENC, keystring=key)
			self.assertEqual( self.password, DEC )
	
if __name__ == "__main__":
	unittest.main()
