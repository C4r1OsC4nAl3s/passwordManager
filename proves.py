# from prompt_toolkit import prompt

# default = "valor default"

# a = str(prompt("introducr: ", default=default))

# print(a)




# from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
# from cryptography.hazmat.backends import default_backend
# from cryptography.hazmat.primitives import padding
# import os

# key = os.urandom(32)
# iv = os.urandom(16)

# def encrypt_aes(plaintext, key, iv):
#     # Asegurar el padding del texto
#     padder = padding.PKCS7(algorithms.AES.block_size).padder()
#     padded_data = padder.update(plaintext.encode()) + padder.finalize()

#     # Crear el cifrador AES
#     cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
#     encryptor = cipher.encryptor()

#     # Cifrar los datos
#     encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
#     return encrypted_data

# def decrypt_aes(encrypted_data, key, iv):
#     # Crear el cifrador AES en modo descifrado
#     cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
#     decryptor = cipher.decryptor()

#     # Desencriptar los datos
#     decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

#     # Eliminar el padding
#     unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
#     decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()

#     return decrypted_data.decode()


# # Ejemplo de texto a cifrar
# plaintext = "mi_super_secreta_contraseña"

# print(f'key: {key}')
# print(f'iv: {iv}')
# # Cifrar el texto
# encrypted_data = encrypt_aes(plaintext, key, iv)
# print(f"Texto encriptado: {encrypted_data}")

# # Desencriptar el texto
# decrypted_data = decrypt_aes(encrypted_data, key, iv)
# print(f"Texto desencriptado: {decrypted_data}")


# # Ejemplo de texto a cifrar
# plaintext = "mi_super_secreta_contraseña"


# # Cifrar el texto
# encrypted_data = encrypt_aes(plaintext, key, iv)
# print(f"Texto encriptado: {encrypted_data}")

# # Desencriptar el texto
# decrypted_data = decrypt_aes(encrypted_data, key, iv)
# print(f"Texto desencriptado: {decrypted_data}")


data = {
    "ids":[
        "hola",
        "adios"
    ]
}


print(data['ids'][1])

