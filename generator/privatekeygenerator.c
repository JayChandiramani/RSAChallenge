#include <stdio.h>
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

    char filename[100]; // Adjust the size as per your requirement
sprintf(filename, "challenge/%s_private_key.pem", argv[3]);
printf("Writing private key to file: %s\n", filename);
FILE *out_file = fopen(filename, "w"); // Open the file in "write" mode
if(out_file == NULL) {
    fprintf(stderr, "Error opening file for writing\n");
    exit(1);
} else {
    PEM_write_RSAPrivateKey(out_file, key, NULL, NULL, 0, 0, NULL);
    fclose(out_file);
    printf("Private key written successfully.\n");
}

  /* Release allocated objects */
  BN_CTX_free (ctx);
  RSA_free(key); /* also frees n, e, d, p, q, dmp1, dmq1, iqmp */
  BN_clear_free (phi);
  BN_clear_free (p1);
  BN_clear_free (q1);

}
