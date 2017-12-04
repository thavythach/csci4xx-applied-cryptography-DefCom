from DefComCryptography import generate_RSA, Generate32BitKey
import json
import os

def create_new_user( username, plaintext_password ):
    	'''

	RETURNS A JSON OBJECT of credentials the user ONLY HAS
	'''
	client_priv, client_pub = generate_RSA()
	
	cert = Generate32BitKey()
	# print( cert )
	return json.dumps({
		"user_name": username,
		"password": plaintext_password,
		"public_key": client_pub,
		"private_key": client_priv,
		"certificate":  cert.decode('unicode-escape') # TODO fix cert.....
	})

if __name__ == "__main__":
    # for idx in range(0,10):
    cwd = os.getcwd()
    print( cwd )
    if not os.path.exists(cwd+'/gen_users'):
        os.makedirs()