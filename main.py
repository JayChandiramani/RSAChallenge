import fnmatch
import glob
from Crypto.PublicKey import RSA
from math import gcd
import subprocess
from Crypto.Cipher import PKCS1_v1_5


# Read and return public key
def get_public_key(public_key_path):
    with open(public_key_path, "r") as keyFile:
        public_key = RSA.import_key(keyFile.read())
    return public_key


# Get modulus of public key
def get_modulus(public_key):
    return public_key.n


# Get P and Q of public key using modulus and common factor
def get_p_and_q(modulus, common_factor):
    p = common_factor
    q = modulus // common_factor
    return p, q


# Generate Private key using the c program from the website by making it an executable.
def run_generate_private_key(p, q, name):
    cmd = ['./generator/gpk', str(p), str(q), str(name)]
    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Error running the private key generator: {e}")
        return None


# Decoder to use generated public keys to decrypt respective .bin files
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


# Using gcd to find common factors and output final data
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


if __name__ == '__main__':
    main()
