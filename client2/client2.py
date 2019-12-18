import socket
import OpenSSL
from OpenSSL import crypto

HOST = "client2"
PORT = 8090

HOST_CA = "ca"
PORT_CA = 8080

def receive_message():
    
    # wait for the receival of a message from client1
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST,PORT))
        s.listen()
        print("listening on port {}".format(PORT))
        while True:
            conn,addr = s.accept()
            print("connected by", addr)

            # receive message
            message = conn.recv(1024)
            if not message:
                print("error receiving message")
                exit
            conn.sendall(b"message ok")
            print("message received is ",message.decode("utf-8"))

            # receive signature and certificate and verify
            signature = conn.recv(4096)
            if not signature:
                print("error receiving signature")
                exit
            conn.sendall(b"signature ok")
            
            certificate = conn.recv(8384)
            if not certificate:
                print("error receiving certificate")
                exit
            conn.sendall(b"certificate ok")

            certificate = crypto.load_certificate(crypto.FILETYPE_PEM,certificate)

            # verify signature with the received certificate
            if not crypto.verify(certificate,signature,message,"sha256"):
                print("signature is correct")

            # check if certificate has been revoked asking for a CRL
            with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as s_ca:
                s_ca.connect((HOST_CA,PORT_CA))
                
                s_ca.sendall(b"getCrl")
                
                print("received from CA: ",s_ca.recv(128).decode("utf-8"))
                
                s_ca.sendall(b"ack")
                
                crl_dump = s_ca.recv(8384)
                crl = crypto.load_crl(crypto.FILETYPE_PEM,crl_dump)
            
            # check if the serial number of client1's certificate is amongst the revoked serial numbers in the CA's CRL
            revoked_list = crl.get_revoked()
            is_revoked = False
            if revoked_list:
                for revoked in revoked_list:
                    if (int(revoked.get_serial().decode("utf-8")) == certificate.get_serial_number()):
                        #this revoked object's serial number is equal to the certificate's serial number
                        is_revoked = True
            if is_revoked:
                print("certificate has been revoked; signature is not valid.")
            else:
                print("certificate is still valid; signature is valid.")
            
            






if __name__ == "__main__":
    receive_message()