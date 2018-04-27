from OpenSSL import crypto
import os
import sys
import datetime
import whois

# CSR Generation tool, to be used to create CSR


# Variables
TYPE_RSA = crypto.TYPE_RSA
HOME = os.getenv("USERPROFILE")
now = datetime.datetime.now()
d = now.date()

# User inputs domain and Private key is created
domainName = input("Enter the Domain: ")
key = crypto.PKey()

# Setting up of the save paths for the .key, .csr, .crt
keypath = str(HOME) + str("/") + str(domainName) + '-' + str(d) + '.key'
csrpath = str(HOME) + "/" + str(domainName) + '-' + str(d) + '.csr'
crtpath = str(HOME) + "/" + str(domainName) + '-' + str(d) + '.crt'


def generatekey():
    # If keypath already exists, it exits the program
    if os.path.exists(str(keypath)):
        print("Certificate already exists in: ")
        print(keypath)
        sys.exit(1)
    #Otherwise it generates a keyfile to the keypath.
    else:
        print("Generating Key for " + str(domainName))
        key.generate_key(TYPE_RSA, 4096)
        keyWriter = open(str(keypath), "w")
        keyWriter.write(str(crypto.dump_privatekey(crypto.FILETYPE_PEM, key)))
        keyWriter.close()


generatekey()


# Generate CSR file
def generatecsr():
    print("How would you like to generate csr data?\n" \
          "1) CQB (For Self-Signed Certs).\n" \
          "2) Specify your own.\n" \
          "3) Attempt Whois Look")

    option = input("Choose (1/2/3): ")
    if option == '1':
        country = 'US'
        state = 'California'
        city = 'USC'
        company = 'Spartans'
        ou = 'Network Operations'
    elif option == '2':
        country = input('Enter your country(ex. US): ')
        state = input("Enter your state(ex. NJ): ")
        city = input("Enter your location(City): ")
        company = input("Enter your organization(ex.RUPL lol) : ")
        ou = input("Enter your organizational unit(ex. IT): ")
    else:
        print("Attempting WHOIS for: ", domainName)
        w = whois.whois(domainName)
        country = str(w.get('country'))
        print(country)
        state = str(w.get('state')).lower().title()
        print(state)
        city = str(w.get('city')).lower().title()
        company = str(w.get('org')).lower().title()
        ou = 'Network Operations'

    req = crypto.X509Req()
    req.get_subject().CN = domainName
    req.get_subject().C = country
    req.get_subject().ST = state
    req.get_subject().L = city
    req.get_subject().O = company
    req.get_subject().OU = ou
    req.set_pubkey(key)
    req.sign(key, "sha256")

    if os.path.exists(str(csrpath)):
        print("Certificate File Exists, aborting.")
        print(csrpath)
    else:
        f = open(str(csrpath), "w")
        f.write(str(crypto.dump_certificate_request(crypto.FILETYPE_PEM, req)))
        f.close()
        print("Success")

    # Generate the certificate
    reply = str(input('Is this a Self-Signed Cert (y/n): ')).lower().strip()

    if reply[0] == 'y':
        cert = crypto.X509()
        cert.get_subject().CN = domainName
        cert.get_subject().C = country
        cert.get_subject().ST = state
        cert.get_subject().L = city
        cert.get_subject().O = company
        cert.get_subject().OU = ou
        cert.set_serial_number(1000)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(315360000)
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(key)
        cert.sign(key, "sha256")

        if os.path.exists(crtpath):
            print("Certificate File Exists in: ")
            print(str(crtpath))
        else:
            f = open(str(crtpath), "w")
            f.write(str(crypto.dump_certificate(crypto.FILETYPE_PEM, cert)))
            f.close()
            print("CRT Stored Here :" + str(crtpath))


generatecsr()

print("Key is saved in:" + keypath)
print("CSR is saved in:" + csrpath)
