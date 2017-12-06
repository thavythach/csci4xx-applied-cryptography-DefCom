from DefComCryptography import Generate32BitKey, Encrypt, Decrypt, SignWithPrivateKey, VerifiySignedWithPublicKey
import json
import unittest
from datetime import timedelta, datetime
from Crypto.PublicKey import RSA 

from config import SERV_PRIV_KEY, SERV_PUB_KEY


def AuthenticationConfirmation( timestamp, now_timestamp, user_name, enc_password, public_key, client_sig, certificate ):
	'''
	Returns 5-tuple of symmetric-key, if replay attack was detected, certificate was signed correctly, signature signed perfectly, and encrypted password.

	:params...:
	'''

	#first check the timestamp
	#print timestamp, now_timestamp
	timestamp_check = detect_replay_protection( timestamp=timestamp, timestamp_against=now_timestamp )
	if not (timestamp_check):
		print "The timestamp is expired, this message might be a replay"
		return

	#get the CA's public key
	f = open( 'CA_PUB_KEY.pem', 'r' )
	CA_PUB_KEY = RSA.importKey(f.read())
	f.close()

	print "hello!"
	#check the certificate to make sure the public key is legitimate
	# cert_check = VerifiySignedWithPublicKey( CA_PUB_KEY, certificate, user_name+public_key )
	# if not (cert_check):
	# 	print "The certificate verification failed, the public key may not be legitimate"
	# 	return

	#check the signature with teh verified public key
	# sig_check = VerifiySignedWithPublicKey( public_key, client_sig, timestamp+user_name+enc_password )
	# if not (sig_check):
	# 	print "The signature verification failed, the message may have been tampered with"
	# 	return

	#decode password and then look for user in the database
	password = serv_priv.decrypt( SERV_PRIV_KEY )

	return password


	
	# # if true decompose msg, else return False
	# msg = timestamp + public_key + password
	# print public_key
	# print client_sig
	# print timestamp
	# ver_check = VerifiySignature( public_key, client_sig, msg )
	# print ver_check
	
	# if ver_check:
	# 	pw = password
	# 	serv_pub = SERV_PUB_KEY.publickey()
		

	# 	# PLACEHOLDER FOR SKYLAR...TO FIX
	# 	goodCert = True
	# 	'''
	# 	user_pub_key_check = decrypt(_buffer=user_creds["certificate"], keystring=ca_pub_key)

	# 	if not (user_pub_key_check == ):
	# 		return "the public key was not signed properly was not correct"
	# 	'''
	# else:
	# 	pass

	# print pw
	# print sym_key

	# return ( sym_key, boolReplay, goodCert, ver_check, pw )

'''
def AuthenticationConfrimation( user_data ):

	user_creds = json.loads(user_data)
	detect_replay_protection(user_creds["timestamp"])

	username = user_creds["user_name"]

	#TODO: open up users file and get pw for the given username
	#also get the public key (ca_pub_key) of the CA

	





	if not (user_creds["password"] == correct_password):
		return "the password was not correct"
	


'''


def detect_replay_protection( timestamp, timestamp_against=datetime.now(), t=30 ):
	'''
	Tells us whether or not the message was a valid message given 30 seconds

	Keyword Arguments:
	timestamp - client/server timestamp
	t - time available: default 30 seconds
	'''

	dt_obj = datetime.strptime( timestamp, '%Y-%m-%d %H:%M:%S' ) 
	dta_obj = datetime.strptime( timestamp_against, '%Y-%m-%d %H:%M:%S' ) 

	if dt_obj <= dta_obj-timedelta( seconds=-t ):
		return True
	return False


class TestAuthenticationConfrimation( unittest.TestCase ):

	def setUp( self ):'''
		with open('user_quantum.json', 'r') as outfile:
			self.json_data = outfile.read()
			self.data = json.loads( self.json_data )
		
		creds = client_protocols.AuthenticationProtocol( data=self.json_data )

		for c in creds:
			print c, creds[c]'''

	def testAuthConf( self ):
			
		'''
		AuthenticationConfirmation( 
			user_name=creds['user_name'], 
			password=creds['password'], 
			public_key=creds['public_key'], 
			timestamp=creds['timestamp'], 
			now_timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"), 
			enc_sym_key=creds['enc_sym_key'], 
			certificate=creds['certificate'], 
			client_sig=creds['client_sig']
		 )'''

if __name__ == "__main__":
	unittest.main()