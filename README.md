# Client-Server Secure Communcation Protocol

## Description

A simple client-server secure communication system for message exchange built using python with the following features:
- handshaking/key exchange
- symmetric encryption
- asymmetric encryption
- hashing/hash comparison
- digital certificate validation

## Local Setup

- Navigate to the `server` folder and add files for a certificate, a respective public key, private key and root certificate by generating or acquiring these files (recommended formats are `*.pem.cert`, `*.pem.key` and `*.pem` respectively)
- In the same folder, create a `.env` file and set the paths/filenames to the above mentioned files with the following variable names respectively: `CERTIFICATE_FILE`, `PUBLIC_KEY_FILE`, `PRIVATE_KEY_FILE` and `ROOT_FILE`
- Navigate to the `client` folder and execut the following command `python app.py`
- Navigate to the `server` folder and execute the following command `python app.py`
- Open a web browser of your choice (preferably Google Chrome) and enter the following URLs in two different tabs: `http://localhost:5001` and `http://localhost:5002`
- In the client application, select your encryption method from the dropdown and then click on `Handshake`
- Upon redirection to the next page, enter your message in the input box and click on `Send`
- Now switch to the server application and click on `Read Message`
- The message you sent should be visible server-side after completing the whole process of handshaking, authentication, encryption, hashing and decryption
- To continue sending messages using the same method, re-use the `/handshake` URL on the client application and the `/receive` URL on the server applications in similar manner as described earlier
- To switch to another encryption method, navigate back to the initial route and repeat the instructions above to achieve exchange of messages using the other method from the dropdown

> [!NOTE]
> Relevant statements are also logged to the CLI for both the client and server application. They can aid in understanding of the control flow and sequence of the protocol as well in testing and debugging the implementation.