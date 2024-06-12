# <p style = "text-align:center;">Understanding Common Factor Attacks:</p>
## <p style = "text-align:center;">An RSA-Cracking Puzzle</p>
### <p style = "text-align:center;">**(My Solution)**</p>

For the original challenge page: [Click Here](http://www.loyalty.org/~schoen/rsa/)

### Index
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
- [Conclusion](#Conclusion)
- [Code Output](#Code-Output)

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

### Gathering the Decrypted Data
Once the `.bin` files are decrypted, the data is as follows:
1. olli sensit enim simulata mente locutam
2. sic fatus meritos aris mactauit honores
3. quattuor ex omni delectae classe carinae
4. Sarpedon ubi tot Simois correpta sub undis
5. externi uenient generi qui sanguine nostrum
6. tum uero ardemus scitari et quaerere causas
7. procedit legio Ausonidum pilataque plenis
8. quandoquidem Ausonios coniungi foedere Teucris
9. debita complerant cum Turni iniuria Matrem
10. si bellum finire manu si pellere Teucros
11. omnia praecepi atque animo mecum ante peregi
12. una omnes iuuenum primi pauperque senatus

<br>

### Following the Clues
First thing that you may notice is that the phrases are in latin. Once translated, they are:
translations of the Latin phrases:

1. olli sensit enim simulata mente locutam
   - "He perceived that she had spoken with a feigned mind."

2. sic fatus meritos aris mactauit honores
   - "Thus having spoken, he offered the deserved honors on the altars."

3. quattuor ex omni delectae classe carinae
   - "Four ships chosen from the entire fleet."

4. Sarpedon ubi tot Simois correpta sub undis
   - "Where Sarpedon and so many (others) were swept away beneath the waves of the Simois."

5. externi uenient generi qui sanguine nostrum
   - "Foreign sons-in-law will come who will mix their blood with ours."
   
6. tum uero ardemus scitari et quaerere causas
   - "Then indeed we burn to inquire and seek the causes."

7. procedit legio Ausonidum pilataque plenis
   - "The legion of Ausonians advances, armed with full..."
   
8. quandoquidem Ausonios coniungi foedere Teucris
   - "Since the Ausonians are joined in treaty with the Trojans."

9. debita complerant cum Turni iniuria Matrem
   - "They had fulfilled the debt owed when the injury of Turnus (was inflicted upon) the Mother."

10. si bellum finire manu si pellere Teucros
    - "If (he is able) to end the war by hand, if (he is able) to drive out the Trojans."

11. omnia praecepi atque animo mecum ante peregi
    - "I have foreseen everything and completed it in my mind beforehand."

12. una omnes iuuenum primi pauperque senatus
    - "Together all the leaders of the youth and the impoverished senate."

As can be seen from the translations, they all reference lines from the poem "The Aeneid" by Virgil. This is an epic 
poem in 12 books that tells the story of the foundation of Rome from the ashes of Troy. The Aeneid focuses on the ideas 
of destiny, journey, and the strengths of Rome. The poem describes the adventures of the main character, Aeneas, as he 
travels with his troops on a quest to reach Italy so that their ancestors can eventually establish Rome. 

Possible common nouns which the clues could be pointing to are:
- **hero** - to describe the main character in "The Aeneid".
- **epic** - to describe the nature of the poem.
- **poem** - to identify the work itself.
- **conflict** - to describe the recurring theme of struggle and battle.
- **journey** - to emphasize the theme of Aeneas's travels and quest.
- **destiny** - to reflect the overarching theme of fate and future.
- **mystery** - to reflect the lack of definition of "Virgil".
- **security** - to reflect the need for finding a new home, needing safety from the Trojans, and the nature of the RSA 
challenge.

<br>

### Conclusion
The process described in this document demonstrates how to find common factors between RSA moduli, generate 
corresponding private keys, and decrypt encrypted messages. The additional challenge of interpreting the decrypted 
messages to guess a common noun provides an engaging puzzle and layer of complexity. By following the steps and using 
the provided code, you can replicate this solution and further your understanding of RSA encryption and cryptographic 
attacks.

<br>

### Code Output
```
Common factor found between: 
29.pem: 152694142162385783686618888186821403945848734132772375554155325544819695590934724814299135220916971737484509612405568086418162043770726700799326623963872138061242702760117376159176139623078412085300737186407581527419178931896640877907619703054754584854553163353493241455027421862729647540952814526935677312669
	p: 13255021146474500311567608978490890706169542435903223652857277300729054042351345458519493118521383085015716518452176586805584419240894763844777441159376627
	q: 11519720751482811146385812311133192303417998415550041021753465194214580372402873638838384449319126355946912236493352175727406874602523474914144252932505647

Decoded message: olli sensit enim simulata mente locutam

82.pem: 145537225208155333040623489167172815406399938049890249262379025982984664388382339661726594420877585266499260424214540772065899792959822064638264854533945764162619503267637586254158342616450406345497689005062848648573206841845485284974488565657664650405817467989476410153578644556790585902720760865443708620403
	p: 13255021146474500311567608978490890706169542435903223652857277300729054042351345458519493118521383085015716518452176586805584419240894763844777441159376627
	q: 10979780688381968099430011208570175937986187772150076579212733080164933735228627132332371397501333648651207282140521368784371971044499241322639006518837889

Decoded message: sic fatus meritos aris mactauit honores

With gcd = 13255021146474500311567608978490890706169542435903223652857277300729054042351345458519493118521383085015716518452176586805584419240894763844777441159376627
------------------------------------------------

Common factor found between: 
9.pem: 141271894161461748845554740499505744736023669938520121389857671795919564242883361768017386907312126047242531791405535588700108982093484659001074694987056061313551090910390126441396967802750103872059129559239102970983983186800554878621505069359050526063509976721166869536923715624901773654123568156524358307971
	p: 12746114090037338638405558348364753170762024925046410448750084084398232130814610810740410270513256665449277121134270816451924978100353060942631979836542387
	q: 11083526568452982131964964676579415811827280156880822536123468319139375792482362247039287720519745289756730597874745518972168015316272870437159014052571633

Decoded message: quattuor ex omni delectae classe carinae

44.pem: 152335791352317039547689002416010056887127284973754084836491827675923832831252286333200834216142757531995390341849756757298385804805254727755425821922057624617220837637455972621379902510032228501704451236469352643834567734521617471066118835875204953912915778777682041583628184600169292904642503844469757923339
	p: 12746114090037338638405558348364753170762024925046410448750084084398232130814610810740410270513256665449277121134270816451924978100353060942631979836542387
	q: 11951547763987634683673438601436121767509351874282663299405070685731493396120292722265185069885336724413008006593488786594035251865666966699914797422311497

Decoded message: Sarpedon ubi tot Simois correpta sub undis

With gcd = 12746114090037338638405558348364753170762024925046410448750084084398232130814610810740410270513256665449277121134270816451924978100353060942631979836542387
------------------------------------------------

Common factor found between: 
71.pem: 135472400918611757666622822789636901038207639581474006488496906937544113899819968264216470405393313301250508761651903965883874352772699986982247519612608840409853757718079903608120168842687889231898954817245684707914621259848016658887023606975529849256590875282759156328281549546230980205644358325222571914637
	p: 12913750264623462276337425644128711174675813336880465068461018681645080047918835348323621347173714301224881492646558739535118834131362641424915974945262413
	q: 10490554497536726770291424974024277135743981883789848554423397865612583558453841955252313841219976974375731593387395755291375663525635781387394235606102849

Decoded message: externi uenient generi qui sanguine nostrum

58.pem: 132009813808533392577123110438741884286561400398429860761027919959189196549797215586297852825375342475728679074489933320371765026814849875692023263110656924146683347962741534495754902097930935910070831755220321417369411370818762253940133993629997648473607090782039210687337530507010114741418840031542303031081
	p: 12913750264623462276337425644128711174675813336880465068461018681645080047918835348323621347173714301224881492646558739535118834131362641424915974945262413
	q: 10222422697004394977725688532088016250886754727118972834058312643416393724627405250255681036829301071437886544959801218835717885646951246124126053948898637

Decoded message: tum uero ardemus scitari et quaerere causas

With gcd = 12913750264623462276337425644128711174675813336880465068461018681645080047918835348323621347173714301224881492646558739535118834131362641424915974945262413
------------------------------------------------

Common factor found between: 
60.pem: 139646679005515842574936981204093845234015477199448080618173487964307244013023085128583197111630542490544238833330384988922749579827248789672128374708926982083208967144764090761687656412100792950654957926632851725398402843385546657630803564543021143148692573369062732915509019257416230830566196883330075238963
	p: 13223199974589313585283471854827363329451685303943205044027865131047695079691108706585803904203301545648101019060082323960067905432343412585098414381558929
	q: 10560732596789832030192265724354506526201260468931970840050031346594368897111616948001231758951513064790326456448687444718560330474622967748448866022511747

Decoded message: procedit legio Ausonidum pilataque plenis

97.pem: 146162993582921807381683018088111565603506954189468271998863032884583087668828227517021359570023475466312440293312149400604293079119484342586683406361798758744709100580799775832717040923452131314993043044025196060906900080741305825223288577054565664034331863477512214203449815958698517366890485107227899018643
	p: 13223199974589313585283471854827363329451685303943205044027865131047695079691108706585803904203301545648101019060082323960067905432343412585098414381558929
	q: 11053526670079822385790669735372993668270169312225360689294382776068335822362421831151226602185143177698224444561986014344905960266587224191285236843997667

Decoded message: quandoquidem Ausonios coniungi foedere Teucris

With gcd = 13223199974589313585283471854827363329451685303943205044027865131047695079691108706585803904203301545648101019060082323960067905432343412585098414381558929
------------------------------------------------

Common factor found between: 
93.pem: 153163191350080004753719541878639679925751357102438057067765648153494919820492752406541777993818669543828409108573301561909800888007187281238501993216174635844061745211925344459533697417725388852473562049060767974408923513912739719270896424056397302060207737757214092400193658968266656005842604773523194251451
	p: 11714776996979588435440066274186746431207255454202665944875994417925671637361979718990753187254963362590523267356636189119746530253241195041886537439669297
	q: 13074358256206665105956844254872464791455783011218926315574506536899756094202061832400538633584249598415024636338845868462911949255730651995021077864973483

Decoded message: debita complerant cum Turni iniuria Matrem

7.pem: 136269636317215868658126726142543242028128679787201513621377420299644359247151157885793577216543689892988935986714087409150506883630386841292060595217129497897100280678153687017820663980404875865314501020301179267627899307057160787226214936662085381326053730017478234531591680965138499420169342895677786825703
	p: 11714776996979588435440066274186746431207255454202665944875994417925671637361979718990753187254963362590523267356636189119746530253241195041886537439669297
	q: 11632285988230946246714551486716113190291520068494163099500564698778303325737351498239617583337540511764131867572374744310703041201014109767591825596334999

Decoded message: si bellum finire manu si pellere Teucros

With gcd = 11714776996979588435440066274186746431207255454202665944875994417925671637361979718990753187254963362590523267356636189119746530253241195041886537439669297
------------------------------------------------

Common factor found between: 
80.pem: 154524252103528874412130038554083106194010767655627703306562705425389302594439847469132251405484274241613967615351312966819881046341220145610188923204343715087697460438214294725260343925469563634489920386457400162171361734743229272393192716994356984959924545704113675103946636897680403846138553658048711956881
	p: 13307692754962545190733618818859249009308397605584526413665519201272482870171338937280605559186730933842250237720203697942551335313430434560173585438909597
	q: 11611648611732904897243454155641820504644131997800178404662512948462510725608238173147299862006170593654770107441399236784472608336434901486792693915427973

Decoded message: omnia praecepi atque animo mecum ante peregi

34.pem: 137196885446016716137754187994637866142967699861655965402716291743230659766466518554979286868222016862330489485118481290531422411428127069161610949525955426894725926369917181283307601278587653616769090814237334704005613463371824612600933387721440443597384194904052142526409405748548072524153356344929340725669
	p: 13307692754962545190733618818859249009308397605584526413665519201272482870171338937280605559186730933842250237720203697942551335313430434560173585438909597
	q: 10309592201462188022034336869196092505517187921536933490404805719918346068596087108484166886684536609804406234976525963761917428482010166946016933613291177

Decoded message: una omnes iuuenum primi pauperque senatus

With gcd = 13307692754962545190733618818859249009308397605584526413665519201272482870171338937280605559186730933842250237720203697942551335313430434560173585438909597
------------------------------------------------
```