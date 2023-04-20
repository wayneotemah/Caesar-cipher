import argparse

# Define a string of all allowed characters for the message
LETTERS = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 !\"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~'

# Define a function to encrypt a message using a Caesar Cipher


def encrypt(message, key):
    cypher = ''
    for letter in message:
        # Check if the letter is in the allowed characters, raise an error otherwise
        if letter not in LETTERS:
            raise ValueError(f'unsupported character: {letter}')
        # Get the index of the letter in the allowed characters
        index = LETTERS.index(letter)
        # Shift the index by the key and wrap around if necessary
        newletter = (index + key) % len(LETTERS)
        # Append the corresponding letter to the cypher text
        cypher += LETTERS[newletter]
    return cypher

# Define a function to decrypt a message using a Caesar Cipher


def decrypt(cypher, key):
    message = ''
    for letter in cypher:
        # Check if the letter is in the allowed characters, raise an error otherwise
        if letter not in LETTERS:
            raise ValueError(f'unsupported character: {letter}')
        # Get the index of the letter in the allowed characters
        index = LETTERS.index(letter)
        # Shift the index back by the key and wrap around if necessary
        newletter = (index - key) % len(LETTERS)
        # Append the corresponding letter to the message
        message += LETTERS[newletter]
    return message


# Define the command-line arguments
if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Encrypt and Decrypt messages using Caesar Cipher')
    parser.add_argument('--encrypt', '-e', help='Encrypt a message', type=str)
    parser.add_argument('--decrypt', '-d', help='Decrypt a message', type=str)
    parser.add_argument(
        '--key', '-k', help='Key to use for encryption/decryption', type=int, default=3)
    args = parser.parse_args()

    # Check if the user wants to encrypt a message
    if args.encrypt:
        message = args.encrypt
        key = args.key
        cypher = encrypt(message, key)
        print(f'Encrypted message: {cypher}')

    # Check if the user wants to decrypt a message
    if args.decrypt:
        cypher = args.decrypt
        key = args.key
        message = decrypt(cypher, key)
        print(f'Decrypted message: {message}')
