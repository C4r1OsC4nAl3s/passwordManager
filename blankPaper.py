

import bcrypt, json
from art import text2art
import os, random, string
from termcolor import colored
from prompt_toolkit import prompt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os

archive = 'constraword.json'
keysJson='keys.json'
key = None
iv = None

def readKeysJson():
    if not os.path.exists(keysJson) or os.stat(keysJson).st_size == 0:
        return {"key":"", "iv":""}

    with open(keysJson, 'r') as file:
        return json.load(file)

# print(readKeysJson())

def generateKeysJson():
    key = os.urandom(32)
    iv = os.urandom(16)

    keysData=readKeysJson()
        
    keysData['key'] = str(key)
    keysData['iv'] = str(iv)

    # print(f'key: {keysData['key']}')
    # print(f'iv: {keysData['iv']}')

    with open(keysJson, 'w') as files:
        json.dump(keysData, files, indent=4)

def encrypt_aes(plaintext):
    keyData = readKeysJson()
    key = eval(keyData['key'])
    iv = eval(keyData['iv'])

    # Asegurar el padding del texto
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext.encode()) + padder.finalize()

    # Crear el cifrador AES
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Cifrar los datos
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return encrypted_data

def decrypt_aes(encrypted_data):

    keyData = readKeysJson()
    key = eval(keyData['key'])
    iv = eval(keyData['iv'])

    # Crear el cifrador AES en modo descifrado
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    # Desencriptar los datos
    decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

    # Eliminar el padding
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()

    return decrypted_data.decode()

def compare_aes(first,second):
    if eval(first) == encrypt_aes(second):
        return True



def readJson():
    if not os.path.exists(archive) or os.stat(archive).st_size == 0:
        return {"pass":[],"ids":[]}

    with open(archive, 'r') as file:
        data = json.load(file)

        
        for dt in data['pass']:
            # if dt == NoneType:
                # break;
            for key,value in dt.items():
            # print(f'{key} -> {value}')
                dt[key] = decrypt_aes(eval(value))
            
        return data

def readEncriptedJson():
    if not os.path.exists(archive) or os.stat(archive).st_size == 0:
        return {"pass":[],"ids":[]}

    with open(archive, 'r') as file:
        data = json.load(file)
      
        return data

def readIdsJson():
    if not os.path.exists(archive) or os.stat(archive).st_size == 0:
        return {"pass":[],"ids":[]}

    with open(archive, 'r') as file:
        data = json.load(file)

        if len(data['ids']) != 0:
            for id in range(len(data['ids'])):
                data['ids'][id] = decrypt_aes(eval(data['ids'][id]))
        return data


def addJson(add_):
    # if add_ != dict:
    #     raise 'no es un dict'

    data = readEncriptedJson()
    data['pass'].append(add_)
    with open(archive, 'w') as file:
        json.dump(data,file , indent=4)


def generate_id(len=5):
    alpha_characters = string.ascii_letters + string.digits
    while True:
        new_id = ''.join(random.choice(alpha_characters) for _ in range(len))
        
        data = readEncriptedJson()
        # if data['ids'] == []:
        #     enId = encrypt_aes(str(new_id))
        #     data['ids'].append(str(enId))

        #     with open(archive, 'w') as file:
        #         json.dump(data, file, indent=4)
        #         return new_id

        ids = [sid for sid in data['ids']]
        if new_id not in ids:
            enId = encrypt_aes(str(new_id))
            print(f'----------------------------------- {str(enId)}')
            data['ids'].append(str(enId))
            print(f'----------------------------------- {data['ids']}')
            print(f'----------------------------------- {data}')


            with open(archive, 'w') as file:
                print('////////////////////////////////////////////////////////')
                print(data)
                json.dump(data, file, indent=4)
                
                return new_id

# generate_id()


def existIdJson(id):
    data = readEncriptedJson()
    for profile in data['pass']:
        if compare_aes(profile['id'], id):
            return True
            # print('True')

# existIdJson('hVToZ');

def readByIdJson(id):
    data = readJson()
    for profile in data['pass']:
        if profile['id'] == id:
            return profile


def updateJson(id, new_data):
    data = readEncriptedJson()
    for profile in data['pass']:
        if compare_aes(profile['id'], id):
            profile.update(new_data)
            break
    
    with open(archive, 'w') as file:
        json.dump(data, file, indent=4)


def deleteJson(id):
    data = readEncriptedJson()
    id = str(encrypt_aes(id))
    data['pass'] = [dt for dt in data['pass'] if dt['id'] != id]
    data['ids'] = [idt for idt in data['ids'] if idt != id]
    with open(archive, 'w') as file:
        json.dump(data, file, indent=4)











# generateKeysJson()


# clave = encrypt_aes('hola mundo')
# print(clave)
# claveDescifrada = decrypt_aes(clave)
# print(claveDescifrada)





print('*' * 100)
print("Welcome, to your favourite PASSWORD MANAGER !!!");
ascii_art = text2art('PassBann', font="slant")
ascii_art = colored(ascii_art, 'yellow')

ascii_ending = text2art('Trust No One', font="slant")
print('*' * 100)
print(ascii_art)
print('*' * 100)


option = None
while(option != 0):
    option = None
    print('\n1) Add new credentials')
    print('2) Show credentials')
    print('3) Update creadentials')
    print('4) Delete creadentials')
    print('0) Exit')

    try:
        option = int(input('Insert a number [0-4]: '))
    except Exception as e:
        print(e)

    if option == 1:
        print('-------------------------------------------------------')
        
        company = str(input('Company name: '))
        user = str(input('User name: '))
        email = str(input('User email: '))
        password = str(input('User password: '))
        print('-------------------------------------------------------')
        id = generate_id()

        new_passings = {
            "id": id,
            "company":company,
            "user": user,
            "email":email,
            "password":password
        }

        
        for key,value in new_passings.items():
            # print(f'{key} -> {value}')
            new_passings[key] = str(encrypt_aes(str(value)))
                
        print('-------------------------------------------------------')
        print(new_passings)
        addJson(new_passings)
        # generateKeysJson()

    elif option == 2:
        data = readJson()
        # print(data)
        if data == None:
            print(data)
            continue

        for dt in data['pass']:
            print(dt)

    elif option == 3:
        id = str(input('Insert id: '))
        
        if existIdJson(id):
            print('--Id Exists')
            defaultValues = readByIdJson(id)

            company = str(prompt('Company name: ', default=defaultValues['company']))
            user = str(prompt('User name: ', default=defaultValues['user']))
            email = str(prompt('User email: ', default=defaultValues['email']))
            password = str(prompt('User password: ', default=defaultValues['password']))

            new_data = {
                "id": id,
                "company":company,
                "user": user,
                "email":email,
                "password":password
            }
            for key,value in new_data.items():
            # print(f'{key} -> {value}')
                new_data[key] = str(encrypt_aes(str(value)))
            updateJson(id, new_data)

    elif option == 4:
        id = str(input('Insert id:'))
        if existIdJson(id):
            deleteJson(id)

    elif option == 0:
        print(ascii_ending)

    else:
        print('Something went WRONG!!')







# new_passings = {
#         "id": id,
#         "company":'hola1',
#         "user": 'hola2',
#         "email": 'hola3',
#         "password": 'hola4'
#     }

# for key,value in new_passings.items():
#     # print(f'{key} -> {value}')
#     new_passings[key] = encrypt_aes(str(value))
#     # print(new_passings[key])
    

# print(new_passings)

# message = 'Xf4R2'
# encryp = encrypt_aes(str(message))
# print(encryp)