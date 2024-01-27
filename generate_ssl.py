from OpenSSL import crypto

'''
Script to generate a self-signed certificate and private key for testing purposes.
'''

# Generate a private key
key = crypto.PKey()
key.generate_key(crypto.TYPE_RSA, 4096)

# Generate a self-signed certificate
cert = crypto.X509()
cert.get_subject().CN = "Testing"
cert.set_serial_number(1000)
cert.gmtime_adj_notBefore(0)
cert.gmtime_adj_notAfter(365 * 24 * 60 * 60)  # Valid for 365 days
cert.set_issuer(cert.get_subject())
cert.set_pubkey(key)
cert.sign(key, 'sha256')

# Save the certificate and private key to files
with open("cert.pem", "wb") as cert_file:
    cert_file.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))

with open("key.pem", "wb") as key_file:
    key_file.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))

print("Certificate and private key generated successfully.")