# text-secure-protocol
Cryptography of Text Secure Protocols &amp; Applications

Registration
The long term public key of the server QSL is given below. X:0xc1bc6c9063b6985fe4b93be9b8f9d9149c353ae83c34a434ac91c85f61ddd1e9
   Y:0x931bd623cf52ee6009ed3f50f6b4f92c564431306d284be7e97af8e443e69a8c
In this part, firstly you are required to generate a long-term private and public key pair sL and QL for yourself. The key generation is described in “Key generation” algorithm in Section 2.3. Then, you are required to register with the server. The registration operation consists of four steps:
1. After you generate your long-term key pair, you should sign your ID (e.g. 18007). The de- tails of the signature scheme is given in the signature generation algorithm in Section 2.3. Then, you will send a message, which contains your student ID, the signature tuple and your long-term public key, to the server. The message format is
{‘ID’: stuID, ‘H’: h, ‘S’: s, ‘LKEY.X’: lkey.x, ‘LKEY.Y’: lkey.y}
where stuID is your student ID, h and s are signature tuple and lkey.x and lkey.y are the x and y and coordinates of your long-term public key, respectively. A sample message is given in ‘samples.txt’.
2. If your message is verified by the server successfully, you will receive an e-mail, which includes your ID, your public key and a verification code: code.
3. If your public key is correct in the verification e-mail, you will send another message to the server to authenticate yourself. The message format is “{‘ID’: stuID, ‘CODE’: code}”, where code is verification code which, you have received in the previous step. A sample message is given below.
{‘ID’: 18007, ‘CODE’: 209682}
4. If you send the correct verification code, you will receive an acknowledgement message via
e-mail, which states that you are registered with the server successfully.
Once you register with the server successfully, you are not required to perform registration step again as the server stores your long-term public key to identify you.

Station-to-Station Protocol
Here, you will develop a python code to implement the STS protocol. For the protocol, you will need the elliptic curve digital signature algorithm described in Section 2.3.
The protocol has seven steps as explained below.
2
1. You are required to generate an ephemeral key pair sA and QA, which denote private and public keys, respectively. The key generation is described in “Key generation” algorithm in Section 2.3
Then, you will send a message, which includes your student ID and the ephemeral public key, to the server. The message format is “{‘ID’: stuID, ‘EKEY.X’: ekey.x, ‘EKEY.Y’: ekey.y”, where ekey.x and ekey.y are the x the y coordinates of your ephemeral public key, respectively. A sample message is given in ‘samples.txt’.
2. After you send your ephemeral public key, you will receive the ephemeral public key QB of the server. The message format is “{‘SKEY.X’: skey.x, ‘SKEY.Y: skey.y}”, where skey.x and skey.y denote the x and y coordinates of QB, respectively. A sample message is given in ‘samples.txt’.

3. After you receive QB, you are required to compute the session key K as follows.
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
