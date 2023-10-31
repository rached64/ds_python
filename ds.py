import ast
import hashlib
import bcrypt
import string,random
import re
import maskpass
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from datetime import datetime
from getpass import getpass

def menu_globale():
    print("\nMenu principal:")
    print("A- Opérations de hachage")
    print("B- Chiffrement (RSA)")
    print("C- Certificat (RSA)")
    print("D- Quitter")

def signup():
    email = introduire_email()
    pwd = introduire_pwd()
    print("Confirmer votre mot de passe: ")
    conf_pwd = introduire_pwd()

    if conf_pwd == pwd:
        with open('Enregistrement.txt', 'w') as file:
            file.write(f"{email}:{pwd}")
            file.write("\n")
        file.close()
        print("Compte créé avec succès.")
    else:
        print("password incorrect! \n")
def main_menu():
    while True:
        print("1- Créer un compte")
        print("2- S'authentifier")
        choix = input('Donnez votre choix : ')
        if choix == "1":
            signup()
        elif choix == "2":
            while True:
                if authentifier():
                    menu_globale()
                    choice = input("Donnez votre choix : ")

                    if choice.upper() == 'A':
                        hash_menu()
                    elif choice.upper() == 'B':
                        rsa_menu()
                    elif choice.upper() == 'C':
                        cert_menu()
                    elif choice.upper() == 'D':
                        print("Au revoir!")
                        break
                    else:
                        print("Choix invalide. Veuillez réessayer.")

def menu_hash():
    print("\nMenu de hachage:")
    print("A- Haché le mot par sha256")
    print("B- Haché le mot en générant un salt (bcrypt)")
    print("C- Attaquer par dictionnaire le mot inséré")
    print("D- Revenir au menu principal")
def hash_menu():
    while True:
        menu_hash()
        hash_choice = input("Donnez votre choix : ")
        if hash_choice.upper() == 'A':
            word = input("Donnez le mot à hacher : ")
            hashed_word = hashlib.sha256(word.encode()).hexdigest()
            print(f"Le mot haché par sha256 : {hashed_word}")
        elif hash_choice.upper() == 'B':
            word = input("Donnez le mot à hacher : ")
            salt = bcrypt.gensalt()
            hashed_word = bcrypt.hashpw(word.encode(), salt).decode()
            print(f"Le mot haché avec salt (bcrypt) : {hashed_word}")
        elif hash_choice.upper() == 'C':
            mot_de_passe_a_verifier = introduire_pwd()
            attaque_par_dictionnaire(mot_de_passe_a_verifier)
        elif hash_choice.upper() == 'D':
            main_menu()
        else:
            print("Choix invalide. Veuillez réessayer.")

def rsa_menu():
    while True:
        print("\nMenu RSA:")
        print("A- Générer les paires de clés dans un fichier")
        print("B- Chiffrer un message par RSA")
        print("C- Déchiffrer le message")
        print("D- Signer un message par RSA")
        print("E- Vérifier la signature du message")
        print("F- Revenir au menu principal")

        rsa_choice = input("Donnez votre choix : ")

        if rsa_choice.upper() == 'A':
            generate_rsa_key_pair()
        elif rsa_choice.upper() == 'B':
            encrypt_message_rsa()
        elif rsa_choice.upper() == 'C':
            decrypt_message_rsa()
        elif rsa_choice.upper() == 'D':
            sign_message_rsa()
        elif rsa_choice.upper() == 'E':
            verify_signature_rsa()
        elif rsa_choice.upper() == 'F':
            break
        else:
            print("Choix invalide. Veuillez réessayer.")

def introduire_email():
    global email
    regex = re.compile(r'([A-Za-z0-9]+[.-_])*[A-Za-z0-9]+@[A-Za-z0-9-]+(\.[A-Z|a-z]{2,})+')
    while True:
        email = input("Donnez votre email : ")
        if re.fullmatch(regex, email):
            return email
        else:
            print("Email invalide")

#Générer un mot de passe
caractères=list(string.ascii_letters+string.digits+'!@#$%^&*()-_£¨')
def generate_password():
    random.shuffle(caractères)
    password=[]
    for i in range(8):
        password.append(random.choice(caractères))
    random.shuffle(password)
    return "".join(password)

#invisible ***
def introduire_pwd():
    global p
    while True:
        print("1-   Générer un mot de passe ")
        print("2-   Crée votre propore mot de passe ")
        pwd = input("Donnez votre choix : ")

        if pwd == "1":
            print(generate_password())
        else :
            p = input("Donnez votre mot de passe : ")
            #p = getpass(prompt='Donnez votre mot de passe : ')
            #p = maskpass.askpass(prompt="Donnez votre mot de passe :", mask="#")
            if len(p) == 8:
                if any(car in string.digits for car in p) and any(car in string.ascii_uppercase for car in p) \
                        and any(car in string.ascii_lowercase for car in p) and any(car in string.punctuation for car in p):
                    p = hashlib.sha256(p.encode()).hexdigest()
                    return p
                else:
                    print("Le mot de passe doit contenir au moins un chiffre, une lettre majuscule, une lettre minuscule, et un caractère spécial.")
            else:
                print("Le mot de passe doit être de longueur 8.")
            return p

#email existe ou nn

def authentifier():
    # Ask the user for their email address
    email = input("Enter your email address: ")
    # Ask the user for their password
    pwd = input("Enter your password: ")
    # Hash the password
    auth = pwd.encode()
    auth_hash = hashlib.sha256(auth).hexdigest()

    # Check if the email exists
    with open('enregistrement.txt', 'r') as file:
        lines = file.readlines()
        """if email not in lines:
            print("Email does not exist.")"""
        for line in lines:
            if line.strip() == f"{email}:{auth_hash}":
                print("Logged in Successfully!")
                print(f"Welcome {email}")
                return True

            print("Authentification échouée.")
    return False


def attaque_par_dictionnaire(mot_de_passe_a_verifier):
    dic=open('dic.txt',mode='r')
    n=0     #track of the number of words tested
    t=datetime.now()    #measure the time taken for the dictionary attack
    for mot in dic:
        mot=mot.strip()     #removes leading and trailing whitespaces from the current word mot
        n+=1
        if hashlib.sha256(mot.encode()).hexdigest()==mot_de_passe_a_verifier or \
           bcrypt.hashpw(mot.encode(), bcrypt.gensalt()).decode() == mot_de_passe_a_verifier:
            print("Mot de passe trouvé ",mot,"pensez à le changer")
            print(n,"mots testés en ",(datetime.now()-t).total_seconds(),"secondes ")
            dic.close()
            return True
    print()
    print("Mot de passe non trouvé, acune haché ne correspond à votre haché ",mot_de_passe_a_verifier)

def generate_rsa_key_pair():
    private_key_file = 'private_key.pem'
    public_key_file = 'public_key.pem'

    key_pair = RSA.generate(1024)

    # Save private key
    with open(private_key_file, 'wb') as f:
        f.write(key_pair.exportKey('PEM'))
    print(f"Clé privée sauvegardée dans {private_key_file}")

    # Save public key
    with open(public_key_file, 'wb') as f:
        f.write(key_pair.publickey().exportKey('PEM'))
    print(f"Clé publique sauvegardée dans {public_key_file}")

def encrypt_message_rsa():
    public_key_file = 'public_key.pem'
    loaded_public_key = RSA.import_key(open(public_key_file).read())
    cipher = PKCS1_OAEP.new(loaded_public_key)
    message = input("Entrer le message à chiffrer : ")
    encrypted_message = cipher.encrypt(message.encode())
    print(f"Message chiffré : {encrypted_message}")

def decrypt_message_rsa():
    private_key_file = 'private_key.pem'
    loaded_private_key = RSA.import_key(open(private_key_file).read())
    cipher = PKCS1_OAEP.new(loaded_private_key)
    encrypted_message = ast.literal_eval(input("Entrer le message chiffré : "))
    decrypted_message = cipher.decrypt(encrypted_message).decode()
    print(f"Message déchiffré : {decrypted_message}")

def sign_message_rsa():
    private_key_file = 'private_key.pem'
    loaded_private_key = RSA.import_key(open(private_key_file).read())
    signer = pkcs1_15.new(loaded_private_key)
    message = input("Entrer le message à signer : ")
    signature = signer.sign(SHA256.new(message.encode()))
    print(f"Signature du message : {signature}")

def verify_signature_rsa():
    public_key_file = 'public_key.pem'
    loaded_public_key = RSA.import_key(open(public_key_file).read())
    verifier = pkcs1_15.new(loaded_public_key)
    message = input("Entrer le message à vérifier : ")
    signature = ast.literal_eval(input("Entrer la signature du message : "))
    try:
        verifier.verify(SHA256.new(message.encode()), signature)
        print("La signature est vérifiée.")
    except (ValueError, TypeError):
        print("La signature est invalide.")

def cert_menu():
    while True:
        print("\nMenu Certificat RSA:")
        print("A- Générer les paires de clés dans un fichier")
        print("B- Générer un certificat autosigné par RSA")
        print("C- Chiffrer un message de votre choix par ce certificat")
        print("D- Revenir au menu principal")

        cert_choice = input("Donnez votre choix : ")

        if cert_choice.upper() == 'A':
            generate_rsa_key_pair()
        elif cert_choice.upper() == 'B':
            generate_self_signed_certificate()
        elif cert_choice.upper() == 'C':
            # Implement certificate encryption logic here
            encrypt_message_with_certificate()
        elif cert_choice.upper() == 'D':
            break
        else:
            print("Choix invalide. Veuillez réessayer.")

def generate_self_signed_certificate():
    private_key_filename = 'private_key.pem'
    loaded_private_key = RSA.import_key(open(private_key_filename).read())
    public_key = loaded_private_key.publickey()
    certificate = f"Certificat RSA\n\n{public_key.exportKey('PEM').decode()}"
    with open('self_signed_certificate.pem', 'w') as f:
        f.write(certificate)
    print("Certificat autosigné généré avec succès.")


def encrypt_message_with_certificate():
    public_key_file = 'public_key.pem'
    message = input("Entrer le message à chiffrer : ")

    try:
        # Load the recipient's public key from the certificate
        recipient_public_key = RSA.import_key(open(public_key_file).read())

        # Use PKCS1_OAEP for encryption
        cipher = PKCS1_OAEP.new(recipient_public_key)

        # Encrypt the message
        encrypted_message = cipher.encrypt(message.encode())

        print(f"Message chiffré : {encrypted_message}")
    except FileNotFoundError:
        print("Le fichier de clé publique n'a pas été trouvé.")
    except ValueError:
        print("Le format de la clé publique n'est pas pris en charge.")


# Run the main menu
main_menu()
