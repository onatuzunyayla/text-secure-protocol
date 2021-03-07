
# Cryptography of Text Secure Protocols &amp; Applications

Phase I: 
Developing software for the Registration and the Station-to-Station (STS) protocols. All coding development will be in Python programming language.
Phase II:
Developing software for receiving messages from other clients
## Phase I: Developing software for the Registration and Station- to-Station Protocols
### Registration

The long term public key of the server QS_L is given below. 

X:0xc1bc6c9063b6985fe4b93be9b8f9d9149c353ae83c34a434ac91c85f61ddd1e9
Y:0x931bd623cf52ee6009ed3f50f6b4f92c564431306d284be7e97af8e443e69a8c

In this part, firstly you are required to generate a long-term private and public key pair sL and QL for yourself. The key generation is described in “Key generation” algorithm in Section 2.3. Then, you are required to register with the server. The registration operation consists of four steps:

1. After you generate your long-term key pair, you should sign your ID (e.g. 18007). The de- tails of the signature scheme is given in the signature generation algorithm in Section 2.3. Then, you will send a message, which contains your student ID, the signature tuple and your long-term public key, to the server. The message format is

{‘ID’: stuID, ‘H’: h, ‘S’: s, ‘LKEY.X’: lkey.x, ‘LKEY.Y’: lkey.y}


where stuID is your student ID, h and s are signature tuple and lkey.x and lkey.y are the x and y and coordinates of your long-term public key, respectively. A sample message is given in ‘samples.txt’.
2. If your message is verified by the server successfully, you will receive an e-mail, which includes your ID, your public key and a verification code: code.
3. If your public key is correct in the verification e-mail, you will send another message to the server to authenticate yourself. The message format is 

“{‘ID’: stuID, ‘CODE’: code}”, 

where code is verification code which, you have received in the previous step. A sample message is given below.

{‘ID’: 18007, ‘CODE’: 209682}

4. If you send the correct verification code, you will receive an acknowledgement message via
e-mail implemented in your API, which states that you are registered with the server successfully.
Once you register with the server successfully, you are not required to perform registration step again as the server stores your long-term public key to identify you.

### Station-to-Station Protocol

Here, STS protocol is implemented. For the protocol, you will need the elliptic curve digital signature algorithm described in Section 2.3.
The protocol has seven steps as explained below.

1. You are required to generate an ephemeral key pair sA and QA, which denote private and public keys, respectively. The key generation is described in “Key generation” algorithm in Section 2.3

Then, you will send a message, which includes your student ID and the ephemeral public key, to the server. The message format is 
“{‘ID’: stuID, ‘EKEY.X’: ekey.x, ‘EKEY.Y’: ekey.y”}, 
where ekey.x and ekey.y are the x the y coordinates of your ephemeral public key, respectively. A sample message is given in ‘samples.txt’.

2. After you send your ephemeral public key, you will receive the ephemeral public key QB of the server. The message format is 
“{‘SKEY.X’: skey.x, ‘SKEY.Y: skey.y}”, 
where skey.x and skey.y denote the x and y coordinates of QB, respectively. A sample message is given in ‘samples.txt’.

3. After you receive Q_B, you are required to compute the session key K as follows.

• T = sAQB
• U = {T.x||T.y||“BeYourselfNoMatterWhatTheySay”}1, where T.x and T.y denote the x and y coordinates of T, respectively.
• K = SHA3 256(U)
A sample for this step is provided in ‘samples.txt’.

4. After you compute K, you should create a message W1, which includes your and the server’s ephemeral public keys, generate a signature SigA using sL for the message W1. After that, you should encrypt the signature using AES in the Counter Mode (AES-CTR). The required operations are listed below.

• W1 = QA.x||QA.y||QB.x||QB.y, where QA.x, QA.y, QB.x and QB.y are the x and y coordinates of QA and QB, respectively.
• (SigA.s,SigA.h)=SignsL(W1)
• Y1 = EK (“s”||SigA.s||“h”||SigA.h)

Then, you should concatenate the 8-byte nonce NonceL and Y1 and send {NonceL||Y1} to the server. Note that, you should convert the ciphertext from byte array to integer. A sample for this step is provided in ‘samples.txt’.
5. If your signature is valid, the server will perform the same operations which are explained in step 4. It creates a message W2, which includes the server’s and your ephemeral public keys, generate a signature SigB using sSL, where sSL is the long-term private key of the server. After that, it will encrypt the signature using AES-CTR.

• W2 = QB.x||QB.y||QA.x||QA.y. (Note that, W1 and W2 are different.)

• (SigB.s,SigB.h) = SignsL(W2)

• Y2 = EK(“s”||SigB.s||“h”||SigB.h)

Finally, it will concatenate the 8-byte nonce NonceSL to Y2 and send {NonceSL||Y2} to you. After you receive the message, you should decrypt it and verify the signature. The signature verification algorithm is explained in Section 2.3. A sample for this step is provided in ‘samples.txt’.

6. Then, the server will send to you another message EK(W3) 2 where, W3 = {Rand||Message}. Here, Rand and Message denote an 8-byte random number and a meaningful message, re- spectively. You need to decrypt the message, and obtain the meaningful message and the random number Rand. A sample for this step is provided in ‘samples.txt’.

7. Finally, you will prepare a message W4 = {(Rand+1)||Message} and send EK(W4) 3 to the server. Sample messages for this step is given below.
W4 : 86987 MessagetoServer : 86987

8. If your message is valid, the server will send a response message as 
E_k(“SUCCESSFUL”||Rand + 2) 

### Elliptic Curve Digital Signature Algorithm (ECDSA)

Here, you will develop a Python code that includes functions for signing given any message and verifying the signature. For ECDSA, you will use an algorithm, which consists of three functions as follows:

• Key generation: A user picks a random secret key 0 < sA < n − 1 and computes the public key QA = (sA)*P.
• Signature generation: Let m be an arbitrary length message. The signature is computed as follows:
1. k←Zn,(i.e.,k is arandom integer in [1,n−2]).
2. R=k·P
3. r = R.x (mod n), where R.x is the x coordinate of R 4. h=SHA3256(m+r) (modn)
5. s=(sA·h+k) (modn)
6. The signature for m is the tuple (h, s).

• Signature verification: Let m be a message and the tuple (s, h) is a signature for m. The verification proceeds as follows:
– V = sP − hQA
– v = V.x (mod n), where V.x is x coordinate of V –h′=SHA3256(m+v) (modn)
– Accept the signature only if h = h′
– Reject it otherwise.

## Phase II: Developing software for receiving messages from other clients


You are required to develop a software for downloading 5 messages from the server, which were uploaded to the server originally by a pseudo-client, which is implemented in the python code ephemeral.py

Phase I is about registration protocol so you must implement the protocol before Phase II and register your long-term public key with the server.
3.1 Registration of ephemeral keys
Before communicating with other clients, you must generate 10 ephemeral public and private key pairs, namely 
(sA0,QA0),(sA1,QA1),(sA2,QA2),...,(sA9,QA9),
where sAi and QAi denote your ith private and public ephemeral keys, respectively. The key generation is described in “Key generation” algorithm in Section 2.3.
Then, you must sign each of your public ephemeral key using your long-term private key. The signatures must be generated for concatenated form of the ephemeral public keys 

(QAi.x||QAi.y). 

Finally, you must sent your ephemeral public keys to the server in the form of

{‘ID’: stuID, ‘KEYID’:i , ‘QAI.X’: QAi.x, ‘QAI.Y’: QAi.y, ‘SI’: si, ‘HI’: hi},

where i is the ID of your ephemeral key. You must start generating your ephemeral keys with IDs from 0 and follow the order. Moreover, you have to store your ephemeral private keys with their IDs.

### Resetting the ephemeral keys

If you forget to store your ephemeral private keys or require to get new messages sent by the pseudo-client, you must sign your ID using your long-term private key and send a message to the server in the form of

{‘ID’: stuID, ‘S’: s, ‘H’: h }.

When the server receives your message, your ephemeral keys will be deleted. After you produce as new set of ephemeral keys and register with the server again, pseudo client will produce a new set of 5 messages for you.

### 3.2 Receiving messages

As mentioned above, you will download 5 messages from the server. In order to download one mes- sage from the server, you must sign your ID using your long-term private key and send a message to the server in the form of

{‘ID’: stuID, ‘S’: s, ‘H’: h }

to download one message from the server as follows

{‘IDB’: stuIDB, ‘KEYID’: i, ‘MSG’: msg , ‘QBJ.X’: QBj.x ,‘QBJ.Y’: QBj.y },

where stuIDB is the ID of the sender, i is the ID of your ephemeral key, which is used to generate session keys, msg contains both the encrypted message and its MAC, and QBj.x and QBj.y are x and y coordinates of the ephemeral public key of the server, respectively.

### 3.2.1 Session Key and msg Generation

As mentioned above, the message that you received includes the ciphertext as well as its MAC,
which is concatenated to the end of the ciphertext. In order to create a message in this way, the
pseudo-client will compute two session keys K_ENC and K_MAC using your and its ephemeral keys
which are QAi and QBj , respectively. Before the computation, the pseudo-client requests your ephemeral key from the server and the server sends your ephemeral key QAi with your key IDi. Then, it computes the session keys as follows:

• T = sBj QAi , where sBj is the jth secret ephemeral key of the pseudo-client.

• U = {T.x||T.y||“NoNeedToRunAndHide”} 5

• K_ENC = SHA3 256(U) AB

• K_MAC = SHA3 256(K_ENC) AB AB

After it computes the session keys, it encrypts the message with K_ENC using AES-CTR6 and
computes HMAC_SHA256 []. of the ciphertext with K_MAC AB

### Decrypting the messages

After you download a message, which is sent by the pseudo-client, from the server, you must gener-
ate session keys firstly. As mentioned above, QBj and i are given to you in the message. Therefore,
you must compute K_ENC and K_MAC as sAiQBj and SHA3_256(K_ENC), respectively. Then, you
must verify the HMAC code and decrypt the message. 
Finally, you must send the decrypted mes- sage with your ID as follows

{‘ID’: stuID, ‘DECMSG’: decmsg}. 

where decmsg is the decrypted message.
