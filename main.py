import os
import uuid
import base64
from dotenv import load_dotenv
from azure.identity import DefaultAzureCredential
from azure.keyvault.keys import KeyClient
from azure.keyvault.keys.crypto import CryptographyClient, EncryptionAlgorithm


load_dotenv()

# Get SP Credentials
credential = DefaultAzureCredential()

vault_uri = os.environ.get('KEY_VAULT_URI')

# initialize key vault
key_client = KeyClient(vault_url=vault_uri, credential=credential)

# Retrieve a Key
print("Fetching key details...")
key = key_client.get_key("vaultern1")

# print('Key Details: {}'.format(key.key))

# intialize cryptography client
crypto_client = CryptographyClient(key, credential=credential)

invitation_code = str(uuid.uuid4())

print("Invitation Code: {}".format(invitation_code))

# Encrypt data
encrypted_code = crypto_client.encrypt(EncryptionAlgorithm.rsa_oaep_256, bytes(invitation_code, 'utf-8'))
ciphered_text = encrypted_code.ciphertext
# endcode it to base64 format
b64encoded_text = base64.urlsafe_b64encode(ciphered_text).decode('utf-8')
print('Encrypted Code: {}'.format(b64encoded_text))

# # Decrypt Data
print('Decrypting Data...')
# Decode to base64 format
b64decoded_text = base64.urlsafe_b64decode(b64encoded_text)
decrypted_code = crypto_client.decrypt(EncryptionAlgorithm.rsa_oaep_256, b64decoded_text)
print('Decrypted Code: {}'.format(decrypted_code.plaintext.decode('utf-8')))