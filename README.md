# <p style = "text-align:center;">Understanding Common Factor Attacks:</p>
## <p style = "text-align:center;">An RSA-Cracking Puzzle</p>
### <p style = "text-align:center;">**(My Solution)**</p>

### Index
- [Disclaimer](#Disclaimer)
- [Overview](#Overview)
- [Setting up the environment](#Setting-up-the-environment)
  - [Installing Packages](#Installing-Packages)
  - [Generating C Executable](#Generating-C-Executable)
- [Code Breakdown](#Code-Breakdown)
  - [Importing Libraries](#Importing-Libraries)
  - [Function Definitions](#Function-Definitions)
    - [Reading Public Keys](#Reading-Public-Keys)
    - [Getting Modulus of Public Key](#Getting-Modulus-of-Public-Key)
    - [Calculating P and Q from Modulus and Common Factor](#Calculating-P-and-Q-from-Modulus-and-Common-Factor)
    - [Generating Private Key](#Generating-Private-Key)
    - [Decoding Encrypted Files](#Decoding-Encrypted-Files)
    - [Finding Common Factors and Decoding Messages](#Finding-Common-Factors-and-Decoding-Messages)
  - [Main Function](#Main-Function)
  - [Running the Script](#Running-the-Script)

### Disclaimer
This is my solution to the RSA Cracking Puzzle seen [Here](http://www.loyalty.org/~schoen/rsa/). This is coded in 
python. In this repository, I only outline how to decrypt the files and get the data. I have **not included** the 
data from the decrypted file nor the English Word such as to not ruin the puzzle at the end.

If you would like to try the challenge for yourself, I would recommend you try it for yourself before going any further 
in this solution. Enjoy cracking the puzzle!

<br>

### Overview
This document provides an overview of the RSA cracking challenge script, which aims to identify common factors between 
RSA public keys, generate corresponding private keys, and decrypt messages. The challenge involves finding the common 
factor between RSA moduli, generating private keys using these factors, and finally decoding the encrypted messages.

Once the messages are decrypted, they will be used as clues to guess a word, which is a common noun. This adds an 
additional layer of complexity and intrigue to the challenge, as participants must not only perform the cryptographic 
cracking but also interpret the decrypted messages to arrive at the final solution.

<br>

### Setting up the environment
Using [PyCharm](https://www.jetbrains.com/pycharm/) is highly recommended for running these commands and algorithm.

#### Importing Challenge Information
Create a new project in PyCharm and name it `RSAChallenge`.

Download the original challenge file from [here](http://www.loyalty.org/~schoen/rsa/challenge.zip) and unzip and move 
the file to the RSAChallenge directory in PyCharm.

#### Installing Packages
Use 

    pip install pycryptodome 
or 

    pip install pycryptodome

in the RSAChallenge directory to install the package.

#### Generating C Executable
Use

    mkdir generator
in the RSAChallenge directory to create a directory called generator. Then use

    cd generator
followed by

    vi privatekeygenerator.c

Once this is complete, press `i`. Then paste the C code below which is taken from the 
[original challenge page](http://www.loyalty.org/~schoen/rsa/private-from-pq.c) and slightly modified to integrate 
seamlessly with python implementation. 
```commandline
#include <stdlib.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/engine.h>

/* Now uses API from OpenSSL 1.1 or later.
 * Please compile this program with -lcrypto to link against the
 * OpenSSL library. */

int main (int argc, char *argv[])
{

  BIGNUM *n = BN_new ();
  BIGNUM *d = BN_new ();
  BIGNUM *e = BN_new ();
  BIGNUM *p = BN_new ();
  BIGNUM *q = BN_new ();
  BIGNUM *p1 = BN_new ();
  BIGNUM *q1 = BN_new ();
  BIGNUM *dmp1 = BN_new ();
  BIGNUM *dmq1 = BN_new ();
  BIGNUM *iqmp = BN_new ();
  BIGNUM *phi = BN_new ();
  BN_CTX *ctx = BN_CTX_new ();
  RSA *key = RSA_new ();

  if (argc < 3)
    {
      fprintf (stderr, "usage: %s p q\n", argv[0]);
      exit (1);
    }

  if (!(BN_dec2bn (&p, argv[1])) || !(BN_dec2bn (&q, argv[2]))) {
      fprintf (stderr, "usage: %s p q\n", argv[0]);
      exit (1);
  }

  if (!(BN_is_prime_ex (p, BN_prime_checks, ctx, NULL)) ||
      !(BN_is_prime_ex (q, BN_prime_checks, ctx, NULL))) {
      fprintf (stderr, "%s: Arguments must both be prime!\n", argv[0]);
      exit (1);
  }

  BN_dec2bn (&e, "65537");

  /* Calculate RSA private key parameters */

  /* n = p*q */
  BN_mul (n, p, q, ctx);
  /* p1 = p-1 */
  BN_sub (p1, p, BN_value_one ());
  /* q1 = q-1 */
  BN_sub (q1, q, BN_value_one ());
  /* phi(pq) = (p-1)*(q-1) */
  BN_mul (phi, p1, q1, ctx);
  /* d = e^-1 mod phi */
  BN_mod_inverse (d, e, phi, ctx);
  /* dmp1 = d mod (p-1) */
  BN_mod (dmp1, d, p1, ctx);
  /* dmq1 = d mod (q-1) */
  BN_mod (dmq1, d, q1, ctx);
  /* iqmp = q^-1 mod p */
  BN_mod_inverse (iqmp, q, p, ctx);

  /* Populate key data structure using RSA_set0 accessor methods */
  RSA_set0_key(key, n, e, d);
  RSA_set0_factors(key, p, q);
  RSA_set0_crt_params(key, dmp1, dmq1, iqmp);

  if (RSA_check_key(key) != 1) {
    printf("OpenSSL reports internal inconsistency in generated RSA key!\n");
    exit(1);
  }

  /* Output the private key in human-readable and PEM forms */
  RSA_print_fp (stdout, key, 5);
  printf("\n");
  PEM_write_RSAPrivateKey (stdout, key, NULL, NULL, 0, 0, NULL);

  /* Release allocated objects */
  BN_CTX_free (ctx);
  RSA_free(key); /* also frees n, e, d, p, q, dmp1, dmq1, iqmp */
  BN_clear_free (phi);
  BN_clear_free (p1);
  BN_clear_free (q1);

}
```

Next click `esc` and enter

    :wq
and run the command

    gcc -o gpk privatekeygenerator.c -lcrypto
to generate an executable file. Next run

    cd ..

<br>

### Code Breakdown
#### Importing Libraries
These libraries must be imported in order for the respective methods to correctly execute.
```python
import fnmatch
import glob
from Crypto.PublicKey import RSA
from math import gcd
import subprocess
from Crypto.Cipher import PKCS1_v1_5
```

#### Function Definitions
###### Reading Public Keys
 - **Purpose:** Reads and returns the public key from a specified key file (`.pem` file).
```python
def get_public_key(public_key_path):
    with open(public_key_path, "r") as keyFile:
        public_key = RSA.import_key(keyFile.read())
    return public_key
```

###### Getting Modulus of Public Key
- **Purpose:** Extracts the modulus from the public key.
```python
def get_modulus(public_key):
    return public_key.n
```

###### Calculating P and Q from Modulus and Common Factor
- **Purpose:** Computes the prime factors p and q from the modulus and a given common factor.
```python
def get_p_and_q(modulus, common_factor):
    p = common_factor
    q = modulus // common_factor
    return p, q
```

###### Generating Private Key
- Purpose: Uses an external C program to generate a private key file (`.pem` file) based on the factors p, q, and 
specified file name.
```python
def run_generate_private_key(p, q, name):
    cmd = ['./generator/gpk', str(p), str(q), str(name)]
    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Error running the private key generator: {e}")
        return None
```

###### Decoding Encrypted Files
- **Purpose:** Uses generated private keys to decrypt respective `.bin` files.
```python
def run_decoder(file1, file2):
    with open("challenge/" + str(file1) + "_private_key.pem", "r") as key_file:
        private_key = RSA.import_key(key_file.read())

    with open("challenge/" + str(file1) + ".bin", "rb") as cipher_file:
        encrypted_data = cipher_file.read()

    cipher = PKCS1_v1_5.new(private_key)
    decoded_msg1 = cipher.decrypt(encrypted_data, None)

    with open("challenge/" + str(file2) + "_private_key.pem", "r") as key_file2:
        private_key2 = RSA.import_key(key_file2.read())

    with open("challenge/" + str(file2) + ".bin", "rb") as cipher_file2:
        encrypted_data2 = cipher_file2.read()

    cipher2 = PKCS1_v1_5.new(private_key2)
    decoded_msg2 = cipher2.decrypt(encrypted_data2, None)

    return decoded_msg1.decode(), decoded_msg2.decode()
```

###### Finding Common Factors and Decoding Messages
- **Purpose:** Finds common factors between moduli, generates private keys, decodes messages, outputs data.
```python
def find_common_factors(moduli):
    for i in range(len(moduli)):
        for j in range(i + 1, len(moduli)):
            gcd_value = gcd(moduli[i][0], moduli[j][0])
            if gcd_value != 1 and gcd_value != moduli[i][0]:

                p1, q1 = get_p_and_q(moduli[i][0], gcd_value)
                p2, q2 = get_p_and_q(moduli[j][0], gcd_value)

                run_generate_private_key(p1, q1, moduli[i][1])
                run_generate_private_key(p2, q2, moduli[j][1])

                decoded_msg1, decoded_msg2 = run_decoder(moduli[i][1], moduli[j][1])

                print(f"Common factor found between: \n{moduli[i][1]}.pem: {moduli[i][0]}\n"
                      f"\tp: {p1}\n"
                      f"\tq: {q1}\n"
                      f"\n"
                      f"Decoded message: {decoded_msg1}\n"
                      f"{moduli[j][1]}.pem: {moduli[j][0]}\n"
                      f"\tp: {p2}\n"
                      f"\tq: {q2}\n"
                      f"\n"
                      f"Decoded message: {decoded_msg2}\n"
                      f"With gcd = {gcd_value}\n"
                      f"------------------------------------------------\n")
```

#### Main Function
- **Purpose:** Gathers all public key files (`.pem`), extracts moduli, and finds common factors.
```python
def main():
    all_key_files = glob.glob("challenge/*.pem")
    public_key_files = [file for file in all_key_files if not fnmatch.fnmatch(file, '*_private_key.pem')]
    moduli = []

    for publicKeyFile in public_key_files:
        public_key = get_public_key(publicKeyFile)
        modulus = get_modulus(public_key)
        name = publicKeyFile.split("/")[-1].split(".")[0]
        moduli.append((modulus, name))

    find_common_factors(moduli)
```

#### Running the Script
- **Purpose:** Entry point for the script execution.
```python
if __name__ == '__main__':
    main()
```

<br>

<br>