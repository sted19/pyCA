import socket
import OpenSSL
from OpenSSL import crypto
import os

HOST = "ca"
PORT = 8080

CN = "CACN"
certificate_file = "{}.crt".format(CN)
key_file = "{}.key".format(CN)
crl_file = "{}.crl".format(CN)

directory = "."
CF  = os.path.join(directory,certificate_file)
KF  = os.path.join(directory,key_file)
CRL = os.path.join(directory,crl_file)

SN = 0

crl = None
certificate = None
key = None


def create_self_signed_certificate():
    global SN, certificate, key

    # generate key
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 2048)

    # define certificate attributes
    cert = crypto.X509()
    cert.get_subject().C    = "IT"
    cert.get_subject().ST   = "Italy"
    cert.get_subject().L    = "Rome"
    cert.get_subject().O    = "."
    cert.get_subject().OU   = "."
    cert.get_subject().CN   = CN

    cert.set_serial_number(0)
    SN += 1

    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(315360000)
    cert.set_issuer(cert.get_subject())  #self signing the certificate (the issuer is the same of the subject)

    cert.set_pubkey(k)
    cert.sign(k, "sha256") 

    # assign to global variables
    certificate = cert
    key = k

    # write to disk certificate and key
    open(CF, "wt").write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("utf-8"))
    open(KF, "wt").write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k).decode("utf-8"))
        

        


def sign_certificate(csr_dump):
    global SN, certificate, key
    if certificate and key:
        private_key = key
        cert = certificate
        csr = crypto.load_certificate_request(crypto.FILETYPE_PEM,csr_dump)

        # create a new certificate starting from the received CSR
        new_cert = crypto.X509()
        new_cert.set_serial_number(SN)
        SN +=1
        new_cert.gmtime_adj_notBefore(0)
        new_cert.gmtime_adj_notAfter(315360000)
        new_cert.set_issuer(cert.get_subject())
        new_cert.set_subject(csr.get_subject())
        new_cert.set_pubkey(csr.get_pubkey())
        new_cert.sign(private_key,"sha256")
        return new_cert
    else:
        print("You are not yet a CA")
        return None        

def revoke(client_certificate):
    revoked = crypto.Revoked()
    revoked.set_serial(str(client_certificate.get_serial_number()).encode("utf-8"))
    revoked.set_rev_date(b"20191217100354Z")                # TODO: adjust with the real revocation date
    revoked.set_reason(b'keyCompromise')
    return revoked


def issue_crl(new_revoked=None):
    global certificate, key, crl
    if not crl:
        crl = crypto.CRL()
        crl.set_lastUpdate(b'20191215152933Z')              # TODO: adjust with real timestamps according to pyOpenSSL documentation
        crl.set_nextUpdate(b'20191217152933Z')              
    if new_revoked:
        crl.add_revoked(new_revoked)
    crl.sign(certificate,key,b"sha256")
    crl_dump = crypto.dump_crl(crypto.FILETYPE_PEM,crl)
    open(CRL, "wt").write(crl_dump.decode("utf-8"))
    return crl_dump


def start_server():
    global crl,certificate,key

    '''
    The CA will be listening on this address for 3 actions:
        - sign
        - revoke
        - getCrl
    clients will connect and ask for the action they need 
    '''
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST,PORT))
        s.listen()
        print("listening on port {}".format(PORT))
        while True:
            conn,addr = s.accept()
            print("connected by", addr)

            action = conn.recv(1024)
            if (not action):
                print("no action provided")
                exit
            action = action.decode("utf-8")

            # sign a certificate
            if (action == "sign"):
                conn.sendall("'sign' action activated. Provide CSR.".encode("utf-8"))
                correct = True
                csr = conn.recv(8384)
                if not csr:
                    print("connection closed by the client")
                    exit  
                csr = csr.decode("utf-8")
                print(csr)
                conn.sendall("request received correctly".encode("utf-8"))
                
                signed_certificate = sign_certificate(csr)
                print("certificate ready to be sent")
                dump_cert = crypto.dump_certificate(crypto.FILETYPE_PEM,signed_certificate)
                conn.sendall(dump_cert)
            
            # revoke a certificate
            elif (action == "revoke"):
                conn.sendall("'revoke' action activated. Provide certificate to revoke".encode("utf-8"))
                client_certificate_dump = conn.recv(8384)
                if not client_certificate_dump:
                    print("error receiving the certificate")
                    exit
                print(client_certificate_dump.decode("utf-8"))
                conn.sendall("certificate received correctly".encode("utf-8"))

                client_certificate = crypto.load_certificate(crypto.FILETYPE_PEM,client_certificate_dump)
                revoked = revoke(client_certificate)
                crl_dump = issue_crl(revoked)

                conn.sendall(crl_dump)

            # get CRL to check revocations
            elif (action == "getCrl"):
                conn.sendall(b"'getCRL' action activated. Sending crl after receiving an ack.")

                print("received from client: ",conn.recv(128).decode("utf-8"))

                # crl should be renewed once in a while. In this example I send always the same global crl, only updating it with new revocations
                if crl:
                    crl_dump = crypto.dump_crl(crypto.FILETYPE_PEM,crl)
                    conn.sendall(crl_dump)
                else:
                    print("crl has not been created yet, let's create one")
                    crl_dump = issue_crl()
                    conn.sendall(crl_dump)
                




if __name__ == "__main__":
    create_self_signed_certificate()
    start_server()


