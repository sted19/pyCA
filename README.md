# pyCA
Demo of a CA (Certification Authority) signing certificates and revoking them (issuing a CRL). This demo uses Python with the package pyOpenSSL. Python scripts are executed in Docker containers.

# Description 
This program is composed of a CA and two clients, namely client<sub>1</sub> and client<sub>2</sub>. The execution is merely a simulation that can be summarized by the following points:

1) the script that will be our CA self-signes a certificate and starts listening for clients that may want the CA to sign their CSRs,
2) client<sub>1</sub> produces a CSR and sends it to the CA, which sends back a signed certificate,
3) client<sub>2</sub> starts listening for incoming messages,
4) client<sub>1</sub> sends a message to client<sub>2</sub>, along with a signature of the message and its certificate (the one previously signed from the CA),
5) client<sub>2</sub> verifies the signature using the certificate, then asks the CA for a CRL, in order to verify the validity of the certificate,
6) client<sub>2</sub> receives the CRL and checks if the certificate has been revoked or is still valid through its serial number (in this case it will be valid).
7) client<sub>1</sub> asks the CA to revoke its certificate (maybe its key has been compromised), then sends a message to client<sub>2</sub> like it did before (this time, though, the certificate is not valid),
8) client<sub>2</sub> again verifies the signature using the cerificate and asks the CA to send it a CRL,
9) client<sub>2</sub> receives the CRL and notices that the serial number of the certificate it received is amongst the revoked in the CRL, meaning that the received certificate is not valid anymore and, consequently, the signature can't be trusted.

 
# How to Execute

After installing both Docker and Docker-compose, to execute the program you just need to run the following two commands:

```shell
docker-compose build
```

```shell
docker-compose up
```

The console will print the output of the programs and show the certificates that are exchanged. At the end of the execution, in the folders where each file.py is, you will find all keys and certificates used, along with CSR and CRL that have been produced.

At the end of execution client<sub>1</sub> terminates, while client<sub>2</sub> and CA keep listening for incoming connections. Shut down them with ctrl+C if you need them to terminate.
