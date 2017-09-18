# AES Image Cryptography

# Introduction

A lesson in AES(ECB) and AES(CBC) block ciphers.
Both algorithms are different in the way blocks feed (or not) into the next block.

# Encryption Method

The following diagrams illustrate the two AES modes used:
![CBC Block Diagram](img/cbc_block_diagram.png)
![ECB Block Diagram](img/ecb_block_diagram.png)

A few things to mention:
   - The same key is used for each block.
   - Each block takes in 16 bytes of plaintext and outputs 16 bytes of ciphertext.

The reason an image can still be recognised after ECB encryption is because 16 bytes of the same plaintext will always become the same ciphertext, no matter the position with respect to the rest of the blocks. So a group of white pixels next to some blue pixels will looks the same in the ciphertext domain as a group of white pixels next to some pink pixels.

The CBC algorithm defeats this vunerability by XORing the ciphertext of the previous blobk with the key, creating dependencies between neighbouring blocks. Now white pixels will be encrypted to a different colour depending on the pixel before that, and before that.

The PPM pixel size is 3 bytes (one byte for each colour, RGB), and the AES block size is 16 bytes. That is
why areas of the same colour in the plaintext domain appear to have a striped
pattern in the ciphertext domain.

This diagram shows how each pixel of a PPM image is encrypted, creating a pattern in the encrypted image:

| |1 | | | 2| | |3 | | | 4 | | | 5 | | | 6 |
|--|--|
| Pixels | r | g | b | r | g | b | r | g | b | r | g | b | r | g | b | r
| Block |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |

Each cell represents a byte. Five full pixels can fit into a block, with the last pixel overlapping into the next block.

# Authors

Cameron A. Craig
