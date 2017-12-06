import json
import os
from base64 import b64encode, b64decode
from Crypto.PublicKey import RSA 
from Crypto.Signature import PKCS1_v1_5 
from Crypto.Hash import SHA256 


def Generate32BitKey():
	return os.urandom(32);

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

def create_new_user( username, plaintext_password ):
	'''
	RETURNS A JSON OBJECT of credentials the user ONLY HAS
	'''
	client_priv, client_pub = generate_RSA()
	
	f = open( 'CA_PRIV_KEY.pem', 'r' )
	CA_PRIV_KEY = RSA.importKey(f.read())
	f.close()

	signer = PKCS1_v1_5.new( CA_PRIV_KEY )


	# f = open( 'CA_PUB_KEY.pem', 'r' )
	# CA_PUB_KEY = RSA.importKey(f.read())
	# f.close()

	# verify = PKCS1_v1_5.new( CA_PUB_KEY )

	
	sigContents = username+client_pub
	h = SHA256.new(sigContents)
	sign = b64encode(signer.sign(h))

	# checkHash = SHA256.new(sigContents)

	# print type(checkHash), checkHash
	# print type(sign), sign

	# gotHash = verify.verify(checkHash,b64decode(sign))
	
	# print type(gotHash),gotHash


	return {
		"user_name": username,
		"password": plaintext_password,
		"public_key": client_pub,
		"private_key": client_priv,
		"certificate": sign
	}




def GenerateServerKeyPair():
	keys = RSA.generate(1024)

	privHandle = open('CA_PRIV_KEY.pem', 'wb')
	privHandle.write( keys.exportKey('PEM') )
	privHandle.close()

	pubHandle = open('CA_PUB_KEY.pem', 'wb')
	pubHandle.write(keys.publickey().exportKey('PEM') )
	pubHandle.close()

if __name__ == "__main__":



	user_pass = [
		('bill', 'gates'),
		('steve', 'jobs'),
		('skylar', 'levey'),
		('thavy', 'thach'),
		('classical', 'cryptography'),
		('quantum', 'cryptography')
	]

	users = []
	for user, pw in user_pass:
		data = create_new_user( username=user , plaintext_password=pw )

		with open('user_' + user + ".json", 'w') as outfile:
			json.dump(data, outfile)

		users.append(json.dumps({
			"user_name": data['user_name'],
			"password": data['password'],
			"public_key": data['public_key']
		}))
	
	with open('RegisteredUsers.py', 'w') as outfile:
		outfile.write("\n".join(users))

	
	# TODO put in a user folder
	# for idx in range(0,10):
	# cwd = os.getcwd()
	# print( cwd )
	# client = cwd+'/client'
	# server = cwd+'/server'

	# if not os.path.exists(client):
	#     os.makedirs(client)
	
	# os.fchdir(client)

	# for user in range(0,5):
	# 	creds = create_new_user( "Shirley_"+user, "bad_password_"+user )
		