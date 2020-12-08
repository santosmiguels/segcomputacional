
'''
***Trabalho de Segurança Computacional - UNB - 1/2020***
**********Gerador/Verificador de Assinaturas************
'''

#Importação das bibliotecas do Python necessárias para criptografia.
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA512, SHA384, SHA256, SHA, MD5
from Crypto import Random
import rsa
from base64 import b64encode, b64decode
import base64

# Definição dã funções
hash = "SHA-256"

def gerar_chave(tamanho_chave):
    random_generator = Random.new().read
    key = RSA.generate(tamanho_chave, random_generator)
    chave_privada, chave_publica = key, key.publickey()
    return chave_publica, chave_privada

def importKey(externKey):
    return RSA.importKey(externKey)

def getpublickey(priv_key):
    return priv_key.publickey()

def cifrar_arquivo(mensagem, chave_privada):
    #RSA encryption protocol according to PKCS#1 OAEP
    print("Cifrando arquivo.")
    cipher = PKCS1_OAEP.new(chave_privada)
    return cipher.encrypt(mensagem)

def decrifrar_arquivo(ciphertext, priv_key):
    #RSA encryption protocol according to PKCS#1 OAEP

    cipher = PKCS1_OAEP.new(priv_key)
    return cipher.decrypt(ciphertext)

def assinar_arquivo(message, priv_key, hashAlg="SHA-256"):
    global hash
    hash = hashAlg
    print ('Assinando documentos/arquivos. ')
    signer = PKCS1_v1_5.new(priv_key)
    if (hash == "SHA-512"):
        digest = SHA512.new()
    elif (hash == "SHA-384"):
        digest = SHA384.new()
    elif (hash == "SHA-256"):
        digest = SHA256.new()
    elif (hash == "SHA-1"):
        digest = SHA.new()
    else:
        digest = MD5.new()
    digest.update(message)
    return signer.sign(digest)


def verificar_assinatura(conteudo, assinatura, chave_publica):
    print ('Verificando assinatura.')
    #print (conteudo)
    #print (assinatura)
    signer = PKCS1_v1_5.new(chave_publica)
    if (hash == "SHA-512"):
        digest = SHA512.new()
    elif (hash == "SHA-384"):
        digest = SHA384.new()
    elif (hash == "SHA-256"):
        digest = SHA256.new()
    elif (hash == "SHA-1"):
        digest = SHA.new()
    else:
        digest = MD5.new()
    digest.update(conteudo)
    return signer.verify(digest, assinatura)

#Definição da função main():
def main():
    print("\n***Trabalho de Segurança Computacional - UNB - 1/2020***")
    print("**********Gerador/Verificador de Assinaturas************\n")

    # Menu de opções
    opcao = 0
    while (opcao != 6):
        print("Opção - 1 - Gerar chave privada e chave publica;")
        print("Opção - 2 - Assinatura digital de documentos/arquivos;")
        print("Opção - 3 - Verificação digital de documentos/arquivos;")
        print("Opção - 4 - Cifrar documentos/arquivos;")
        print("Opção - 5 - Decifrar documentos/arquivos;")
        print("Opção - 6 - Sair.")

        opcao = int(input("Escolha a opção desejada: "))

        if (opcao == 1): # Geração da chave privada e chave pública.
            print("****Gerar chave privada e chave publica****")
            tamanho_chave = int(input ("Entre com o tamanho desejado da chave: ")) # A variável tamanho recebe o tamnho desejado da chave e é convertida para o tipo int.
            (chave_publica, chave_privada) = gerar_chave(tamanho_chave) # Chamada da função gerar_chave
            print ("Foram geradas as chaves (privada e publica):")
            print (chave_publica)
            print (chave_privada)
            print ('\n')

        elif (opcao == 2):
            print("****Assinatura digital de documentos/arquivos****")
            #print(public)
            #print(private)

            arq_entrada = input("Entre com o nome do arquivo a ser assinado: ")
            #print('O nome do arquivo de entrada é: ', arq_entrada)
            abre_arq = open(arq_entrada, "r")
            conteudo = abre_arq.read()
            abre_arq.close()
            print("O conteúdo do arquivo é: \n{}\n".format(conteudo))
            assinatura = b64encode(assinar_arquivo(bytes(conteudo, encoding="UTF-8"), chave_privada, "SHA-512")) #Chamada da função assinar.

            abre_arq = open("hasharq.txt", "w")
            abre_arq.write(str(assinatura, encoding="UTF-8"))
            abre_arq.close()

            print("A assinatura (hash) do arquivo é: ")
            print(assinatura)  # Imprimi o resultado retornado que é o hash do arquivo.
            print("Foi criado o arquivo hasharq.txt com o conteúdo da assinatura.\n")

        elif (opcao == 3):
            print("****Verificação digital de documentos/arquivos****")

            arq_entrada = input("Entre com o nome do arquivo a ser verificado: ")
            # print('O nome do arquivo de entrada é: ', arq_entrada)
            abre_arq = open(arq_entrada, "r")
            conteudo = abre_arq.read()
            abre_arq.close()
            print("O conteúdo do arquivo para verificação é: \n {}".format(conteudo))
            print (bytes(conteudo, encoding="UTF-8"))
            print (conteudo)
            #print (assinatura)

            verificacao = verificar_assinatura(bytes(conteudo, encoding="UTF-8"), b64decode(assinatura), chave_publica)
            #verify = verify(msg1, b64decode(signature), public)
            # verify = rsa.verify(bytes(msg1,encoding="UTF-8"), b64decode(signature), public)
            # verify1 = verify(bytes(msg1, encoding="UTF-8"), b64decode(signature), public)
            print (assinatura)
            print(verificacao)


        elif (opcao == 4):
            print("****Cifrar documentos/arquivos****")
            arq_entrada = input("Entre com o nome do arquivo para cifrar: ")
            # print('O nome do arquivo de entrada é: ', arq_entrada)
            abre_arq = open(arq_entrada, "r")
            conteudo = abre_arq.read()
            abre_arq.close()
            print("O conteúdo do arquivo é: \n{}\n".format(conteudo))
            print(bytes(conteudo, encoding="UTF-8"))

            arq_cifrado = b64encode(cifrar_arquivo(bytes(conteudo, encoding="UTF-8"), chave_privada))
            #print(arq_cifrado)

            abre_arq = open("hash_cifrado.txt", "w")
            abre_arq.write(str(arq_cifrado, encoding="UTF-8"))
            abre_arq.close()

            print("A conteúdo do hash cifrado é: ")
            print (arq_cifrado)  # Imprimi o resultado retornado que é o hash do arquivo.
            #print (bytes(arq_cifrado, encoding="UTF-8"))
            print("Foi criado o arquivo hash_cifrado.txt com o conteúdo do hash_cifrado.\n")

        elif (opcao == 5):
            print("****Decifrar documentos/arquivos****")

            abre_arq = open("hash_cifrado.txt", 'r')
            conteudo = abre_arq.read()
            abre_arq.close()
            print ("O conteudo do arquivo para decifrar é: ")
            print (conteudo)
            decifrar = decrifrar_arquivo(b64decode(conteudo), chave_privada)
            #print (bytes(decrifrar, encoding="UTF-8"))
            print (decifrar)

        else:
            print("Sistema finalizado.")

if __name__ == '__main__':
    main()
