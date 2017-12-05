import json
import os
from Crypto.PublicKey import RSA 


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
	
	cert = Generate32BitKey()
	# print( cert )
	return {
		"user_name": username,
		"password": plaintext_password,
		"public_key": client_pub,
		"private_key": client_priv,
		"certificate":  cert.decode('unicode-escape') 
		# encrypted_hash of the public_key and encrypted with the CA's private key
	}

def GenerateServerKeyPair():
	keys = RSA.generate(1024)

	privHandle = open('SERV_PRIV_KEY.pem', 'wb')
	privHandle.write( keys.exportKey('PEM') )
	privHandle.close()

	pubHandle = open('SERV_PUB_KEY.pem', 'wb')
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
		