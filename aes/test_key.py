
import numpy as np
from Crypto.Cipher import AES
from aes.lut import sbox, RC

def recover_key(key_round: np.ndarray) -> np.ndarray:
    """Get the original key from a list of 10 round keys.

    Args:
        key_round (list): The list of round keys.

    Returns:
        list: The original key as list of 16 bytes.
    """
    key_round = np.reshape(key_round, (4,4)).transpose()
    for round in range(0,10):
        key_round_previous = key_round
        key_round[:,3] = key_round_previous[:,3] ^ key_round_previous[:,2]
        key_round[:,2] = key_round_previous[:,2] ^ key_round_previous[:,1]
        key_round[:,1] = key_round_previous[:,1] ^ key_round_previous[:,0]
        key_round[:,0] = function_g(key_round[:,3], 9 - round) ^ key_round_previous[:,0]
        
    return np.array(key_round, dtype=np.uint8).flatten(order='F')

def function_g(k: list, round: int) -> int:
    """Calculate the g function when recovering the key.

    Args:
        k (list): The key to calculate the g function for.
        round (int): The current round.

    Returns:
        int: The calculated result for the g function.
    """
    result = []
    # rotation
    k = np.roll(k, -1)
    # sub
    temp = []
    for i in range(0,4):
        temp.append(sbox(int(hex(k[i]),16)))
    # rcon
    rcon = [0x00, 0x00, 0x00]
    rcon.insert(0,RC[round])
    for byte_a, byte_b in zip(rcon,temp):
        result.append(byte_a ^ int(byte_b,16))
    return result


def test_key(last_round_key: np.ndarray, plaintext, ciphertext) -> 'tuple(bool, str)':
    """Tests last round key with given encryption pair."""

    # Recover key from last round key
    key = recover_key(last_round_key)
    
    # perform AES encryption with derived key
    aes = AES.new(key.tobytes(), AES.MODE_ECB)
    calculated_cipher = np.array(bytearray(aes.encrypt(np.array(plaintext, dtype=np.uint8).tobytes())),
                                 dtype=np.uint8)
    
    # check result with data
    if (calculated_cipher == ciphertext).all():
        return True, ''.join([hex(x)[2:].zfill(2).upper() for x in key.tolist()])
    else:
        return False, None
