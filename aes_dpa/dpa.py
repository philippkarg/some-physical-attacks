# -*- Mode: Python; tab-width: 4; coding: utf8 -*-
"""
DPA Attack on last round key of AES.

Please implement your attack in the function perform_dpa().
"""
import reader as rd
import numpy as np  # numeric calculations and array
from itertools import product
from aes.lut import sbox_inv

#####################################################################
# Functions #########################################################
#####################################################################

class DPA:

    def __init__(self, traces_path: str):
        self.reader = rd.DPAReader(traces_path)
        self.window_size = len(self.reader.ciphertexts)  
    
    def __hw(self, n: int) -> int:
        """Compute the Hamming weight of a given integer.

        Args:
            n (int): The integer to get the Hamming weight for.

        Returns:
            int: The Hamming weight of the given integer.
        """
        c = 0
        while n:
            c +=1
            n &= n-1
        return c

    def __generate_key_hyp(self) -> list:
        """Generate a list of all possible key hypotheses for 1 key byte.

        Returns:
            list: The list of all possible key hypotheses.
        """
        key = []
        for k in range(0,256):
            key.append(k)
        return key

    def __compute_T(self) -> np.ndarray:
        """Generate the T matrix out of the traces.

        Args:
            reader (Reader): The Reader object to read the traces.

        Returns:
            np.ndarray: The T matrix.
        """
        # extract window
        traces_size = len(self.reader.traces[0])
        self.reader.traces[:self.window_size, :traces_size]

        return np.reshape(self.reader.traces, (self.window_size,traces_size))

    def __compute_V(self, byte: int, key: list) -> np.ndarray:
        """Compute the V matrix.

        Args:
            reader (Reader): The reader class to read the plaintexts and ciphertexts.
            byte (int): The current byte to compute the V matrix for.
            key (list): The list of key hypotheses.

        Returns:
            np.ndarray: The V matrix.
        """
        d = self.reader.get_ciphertext_column(byte)
        d = d[:self.window_size]
        v = [[0 for _ in range(len(key))] for _ in range(len(d))]
        
        for i, j in product(range(len(d)),range(len(key))):
            v[i][j] = sbox_inv(d[i]^ key[j])
            
        return np.array(v)

    def __compute_H(self, v: np.ndarray) -> np.ndarray:
        """Generate the H matrix containing the Hamming weights of the V matrix.

        Args:
            v (np.ndarray): The V matrix to generate the H matrix from.

        Returns:
            np.ndarray: The H matrix.
        """
        h = [[0 for _ in range(len(v[0]))] for _ in range(len(v))]

        for i, j in product(range(len(v)),range(len(v[0]))):
            h[i][j] = self.__hw(int(v[i,j],16))

        return np.array(h)

    # generate R correlation matrix 
    def __compute_R(self, t: np.ndarray, h: np.ndarray) -> np.ndarray:
        """Compute the correlation matrix R.

        Args:
            t (np.ndarray): The T matrix.
            h (np.ndarray): The H matrix.

        Returns:
            np.ndarray: The correlation matrix R.
        """
        result = []
        tv = t - t.mean(axis=0)
        hv = h - h.mean(axis=0)
        tvss = (tv * tv).sum(axis=0)
        hvss = (hv * hv).sum(axis=0)

        result = np.matmul(tv.transpose(), hv) / np.sqrt(np.outer(tvss, hvss))
        result[np.isnan(result)] = 0
        return np.maximum(np.minimum(result, 1.0), -1.0)

    def perform_dpa(self) -> np.ndarray:
        # given values:
        # ciphertexts[trace #][byte] = ciphertext        (T,B)   np.uint8
        # traces[trace #][sample] = power-consumption    (T,S)   np.uint8
        # Sizes
        # T, S = traces.shape    #T:number of traces     #S:number of samples
        # B, K = 16, 256         #B:number of bytes      #K:number of key hypotheses

        # type conversion:
        # traces = np.float32(traces)
        
        key = self.__generate_key_hyp()
        round_key = []
        t_matrix = self.__compute_T()

        # For all bytes in the AES state
        for byte in range(16):
            # First compute the V-matrix
            v_matrix = self.__compute_V(byte, key)
            # Compute the Hamming-Weight Matrix using the V-matrix
            h_matrix = self.__compute_H(v_matrix)
            # Finally use the traces & Hamming-weights to compute the correlation matrix
            r_matrix = np.absolute(np.array(self.__compute_R(t_matrix, h_matrix)).transpose())
            # Find the entry with maximum (absolute) correlation & append to the round key
            round_key_byte = int(np.where(r_matrix ==  np.amax(r_matrix))[0][-1])
            round_key.append(round_key_byte)
            print("Last Round Key: " + "".join(hex(x)[2:].zfill(2) for x in round_key).upper(), end="\r")
            
        print("")
        
        return np.array(round_key)

