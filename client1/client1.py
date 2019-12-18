import socket
import OpenSSL
import time
from OpenSSL import crypto

HOST_CA = "ca"
PORT_CA = 8080

HOST_USER = "client2"
PORT_USER = 8090

certificate = None
key = None


def create_csr(CN=None,C=None,ST=None,L=None,O=None,OU=None):
    global key

    # generate key
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 2048)

    # generate CSR
    req = crypto.X509Req()

    if CN:
        req.get_subject().CN   = CN
    if C:
        req.get_subject().C    = C
    if ST:
        req.get_subject().ST   = ST
    if L:
        req.get_subject().L    = L
    if O:
        req.get_subject().O    = O
    if OU:
        req.get_subject().OU   = OU

    req.set_pubkey(k)
    req.sign(k,"sha256")

    key = k
    
    # store their values
    private_key = crypto.dump_privatekey(crypto.FILETYPE_PEM, k)
    csr = crypto.dump_certificate_request(crypto.FILETYPE_PEM, req)
    open("pkey.key","wt").write(private_key.decode("utf-8"))
    open("req.csr","wt").write(csr.decode("utf-8"))
    return private_key,csr


def CA_sign(csr):
    global certificate
    with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as s:
        connected = False
        while not connected:
            try:
                s.connect((HOST_CA,PORT_CA))
                connected = True
                print("connection successfull")
            except:
                print("connection refused, trying again")
                time.sleep(1)
        s.sendall("sign".encode("utf-8"))
        answer = s.recv(1024)
        print("received from CA: ", answer.decode("utf-8"))
        
        # send the csr to have a signed certificate in return 
        s.sendall(csr)
        answer = s.recv(1024)
        print("received from CA: ", answer.decode("utf-8"))

        # store the received certificate both in a global variable and on disk
        signed_dump = s.recv(8384)
        certificate = crypto.load_certificate(crypto.FILETYPE_PEM,signed_dump)
        open("signed_certificate.cer","wt").write(signed_dump.decode("utf-8"))
        return signed_dump


def ask_for_revokation(certificate_dump):
    with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as s:
        s.connect((HOST_CA,PORT_CA))
        s.sendall("revoke".encode("utf-8"))
        answer = s.recv(1024)
        print("received from CA: ", answer.decode("utf-8"))
        
        # send the certificate to revoke
        s.sendall(certificate_dump)
        answer = s.recv(1024)
        print("received from CA: ", answer.decode("utf-8"))

        # receive and print the crl with your revocation inside
        crl_dump = s.recv(8384)
        print(crl_dump.decode("utf-8"))
        

def send_message(message):
    global certificate,key
    with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as s:
        s.connect((HOST_USER,PORT_USER))
        print("sending signed message")

        # sign the message with your private key
        signature = crypto.sign(key,message.encode("utf-8"),"sha256")

        # send message
        s.sendall(message.encode("utf-8"))
        print(s.recv(128).decode("utf-8"))

        #send signature
        s.sendall(signature)
        print(s.recv(128).decode("utf-8"))

        #send certificate
        s.sendall(crypto.dump_certificate(crypto.FILETYPE_PEM,certificate))
        print(s.recv(128).decode("utf-8"))





if __name__ == "__main__":
    # generate a CSR and ask the CA to sign it 
    pkey,csr = create_csr("client1","IT","Italy","Rome")
    certificate_dump = CA_sign(csr)

    # send a message to client2
    send_message("hello, I'm client1")

    # sleep 5 seconds, then ask for revocation of the certificate, then send the same message sent before. This time client2 will notice that the certificate is not valid anymore
    time.sleep(3)
    ask_for_revokation(certificate_dump)
    send_message("hello, I'm client1")