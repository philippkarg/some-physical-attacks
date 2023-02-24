# -*- Mode: Python; tab-width: 4; coding: utf8 -*-
"""
DFA attack against AES.

Please implement your attack in the function perform_dfa()
"""

import numpy as np
import reader as rd
from aes.lut import SBOX_INV, gfmul256

class DFA:
    
    def __init__(self, input_path: str) -> None:
        self.reader = rd.DFAReader(input_path)

    @staticmethod
    def equation(index_x: int, index_y: int, c: 'list[int]', f_c: 'list[int]', multiplier: int) -> 'list[tuple]':
        k_candidates = []
        if multiplier > 1:
            for k_x in range(256):
                for k_y in range(256):
                    if (SBOX_INV[c[index_x] ^ k_x] ^ SBOX_INV[f_c[index_x] ^ k_x]) == gfmul256((SBOX_INV[c[index_y] ^ k_y] ^ SBOX_INV[f_c[index_y] ^ k_y]), multiplier):
                        k_candidates.append((k_x, k_y))
        else:
            for k_x in range(256):
                for k_y in range(256):
                    if (SBOX_INV[c[index_x] ^ k_x] ^ SBOX_INV[f_c[index_x] ^ k_x]) == (SBOX_INV[c[index_y] ^ k_y] ^ SBOX_INV[f_c[index_y] ^ k_y]):
                        k_candidates.append((k_x, k_y))
                        
        return k_candidates

    @staticmethod
    def filter_candidates(k_candidates_x: 'list[tuple]', k_candidates_y: 'list[tuple]', k_candidates_z: 'list[tuple]') -> 'list[tuple]':
        filtered_candidates = []
        for k_candidate_x in k_candidates_x:
            for k_candidate_y in k_candidates_y:
                for k_candidate_z in k_candidates_z:
                    if k_candidate_x[1] == k_candidate_y[1] == k_candidate_z[1]:
                        filtered_candidates.append((k_candidate_x[0], k_candidate_y[0], k_candidate_z[0], k_candidate_x[1]))
                        
        return filtered_candidates

    def col_0(self, c: 'list[int]', f_c: 'list[int]') -> 'list[tuple]':
        """Calculate the first column of the key matrix.

        Args:
            c (list[int]): The list of correct ciphertext bytes.
            f_c (list[int]): The list of faulty ciphertext bytes.

        Returns:
            list[tuple]: List of possible key combinations.
        """
        # SB^-1(c0 ^ k0) ^ SB^-1(f0 ^ k0) = 2*(SB^-1(c13 ^ k13) ^ SB^-1(f13 ^ k13))
        k_candidates_0 = self.equation(index_x=0, index_y=13, c=c, f_c=f_c, multiplier=2)
        # SB^-1(c10 ^ k10) ^ SB^-1(f10 ^ k10) = SB^-1(c13 ^ k13) ^ SB^-1(f13 ^ k13)
        k_candidates_10 = self.equation(index_x=10, index_y=13, c=c, f_c=f_c, multiplier=1)
        # SB^-1(c7 ^ k7) ^ SB^-1(f7 ^ k7) = 3*(SB^-1(c13 ^ k13) ^ SB^-1(f13 ^ k13))
        k_candidates_7 = self.equation(index_x=7, index_y=13, c=c, f_c=f_c, multiplier=3)
                
        return self.filter_candidates(k_candidates_0, k_candidates_10, k_candidates_7)

    def col_1(self, c: 'list[int]', f_c: 'list[int]') -> 'list[tuple]':
        """Calculate the second column of the key matrix.

        Args:
            c (list[int]): The list of correct ciphertext bytes.
            f_c (list[int]): The list of faulty ciphertext bytes.

        Returns:
            list[tuple]: List of possible key combinations.
        """
        # SB^-1(c1 ^ k1) ^ SB^-1(f1 ^ k1) = SB^-1(c4 ^ k4) ^ SB^-1(f4 ^ k4)
        k_candidates_1 = self.equation(index_x=1, index_y=4, c=c, f_c=f_c, multiplier=1)
        # SB^-1(c14 ^ k14) ^ SB^-1(f14 ^ k14) = 3*(SB^-1(c4 ^ k4) ^ SB^-1(f4 ^ k4))
        k_candidates_14 = self.equation(index_x=14, index_y=4, c=c, f_c=f_c, multiplier=3)
        # SB^-1(c11 ^ k11) ^ SB^-1(f11 ^ k11) = 2*(SB^-1(c4 ^ k4) ^ SB^-1(f4 ^ k4))
        k_candidates_11 = self.equation(index_x=11, index_y=4, c=c, f_c=f_c, multiplier=2)
                
        return self.filter_candidates(k_candidates_1, k_candidates_14, k_candidates_11)

    def col_2(self, c: 'list[int]', f_c: 'list[int]') -> 'list[tuple]':
        """Calculate the third column of the key matrix.

        Args:
            c (list[int]): The list of correct ciphertext bytes.
            f_c (list[int]): The list of faulty ciphertext bytes.

        Returns:
            list[tuple]: List of possible key combinations.
        """
        # SB^-1(c15 ^ k15) ^ SB^-1(f15 ^ k15) = SB^-1(c8 ^ k8) ^ SB^-1(f8 ^ k8)
        k_candidates_15 = self.equation(index_x=15, index_y=8, c=c, f_c=f_c, multiplier=1)
        # SB^-1(c5 ^ k5) ^ SB^-1(f5 ^ k5) = 3*(SB^-1(c8 ^ k8) ^ SB^-1(f8 ^ k8))
        k_candidates_5 = self.equation(index_x=5, index_y=8, c=c, f_c=f_c, multiplier=3)
        # SB^-1(c2 ^ k2) ^ SB^-1(f2 ^ k2) = 2*(SB^-1(c8 ^ k8) ^ SB^-1(f8 ^ k8))
        k_candidates_2 = self.equation(index_x=2, index_y=8, c=c, f_c=f_c, multiplier=2)
                
        return self.filter_candidates(k_candidates_15, k_candidates_5, k_candidates_2)

    def col_3(self, c: 'list[int]', f_c: 'list[int]') -> 'list[tuple]':
        """Calculate the fourth column of the key matrix.

        Args:
            c (list[int]): The list of correct ciphertext bytes.
            f_c (list[int]): The list of faulty ciphertext bytes.

        Returns:
            list[tuple]: List of possible key combinations.
        """
        # SB^-1(c12 ^ k12) ^ SB^-1(f12 ^ k12) = 3*(SB^-1(c6 ^ k6) ^ SB^-1(f6 ^ k6))
        k_candidates_12 = self.equation(index_x=12, index_y=6, c=c, f_c=f_c, multiplier=3)
        # SB^-1(c9 ^ k9) ^ SB^-1(f9 ^ k9) = 2*(SB^-1(c6 ^ k6) ^ SB^-1(f6 ^ k6))
        k_candidates_9 = self.equation(index_x=9, index_y=6, c=c, f_c=f_c, multiplier=2)
        # SB^-1(c3 ^ k3) ^ SB^-1(f3 ^ k3) = SB^-1(c6 ^ k6) ^ SB^-1(f6 ^ k6)
        k_candidates_3 = self.equation(index_x=3, index_y=6, c=c, f_c=f_c, multiplier=1)
                
        return self.filter_candidates(k_candidates_12, k_candidates_9, k_candidates_3)

    @staticmethod
    def find_matching_columns(possible_columns_0: 'list[tuple]', possible_columns_1: 'list[tuple]') -> tuple:
        matching_columns = []
        for possible_byte_0 in possible_columns_0:
                if possible_byte_0 in possible_columns_1:
                    matching_columns.append(possible_byte_0)
                    
        if len(matching_columns) == 0:
            print("No matching columns found!")
            return None

        if len(matching_columns) > 1:
            print("More than one matching column found!")
            return None
                    
        return matching_columns[0]

    def perform_dfa(self):
        key = np.zeros(16, dtype=np.uint8)

        # ...
        key_hypotheses_0 = [
            self.col_0(self.reader.ciphertexts[0], self.reader.faulty_ciphertexts[0]),
            self.col_1(self.reader.ciphertexts[0], self.reader.faulty_ciphertexts[0]),
            self.col_2(self.reader.ciphertexts[0], self.reader.faulty_ciphertexts[0]),
            self.col_3(self.reader.ciphertexts[0], self.reader.faulty_ciphertexts[0])
        ]
        key_hypotheses_1 = [
            self.col_0(self.reader.ciphertexts[1], self.reader.faulty_ciphertexts[1]),
            self.col_1(self.reader.ciphertexts[1], self.reader.faulty_ciphertexts[1]),
            self.col_2(self.reader.ciphertexts[1], self.reader.faulty_ciphertexts[1]),
            self.col_3(self.reader.ciphertexts[1], self.reader.faulty_ciphertexts[1])
        ]
        
        correct_column_0 = self.find_matching_columns(key_hypotheses_0[0], key_hypotheses_1[0])
        correct_column_1 = self.find_matching_columns(key_hypotheses_0[1], key_hypotheses_1[1])
        correct_column_2 = self.find_matching_columns(key_hypotheses_0[2], key_hypotheses_1[2])
        correct_column_3 = self.find_matching_columns(key_hypotheses_0[3], key_hypotheses_1[3])
        
        key = [
        #   k0                      k1                      k2                      k3 
            correct_column_0[0],    correct_column_1[0],    correct_column_2[2],    correct_column_3[2],
        #   k4                      k5                      k6                      k7
            correct_column_1[3],    correct_column_2[1],    correct_column_3[3],    correct_column_0[2],
        #   k8                      k9                      k10                     k11
            correct_column_2[3],    correct_column_3[1],    correct_column_0[1],    correct_column_1[2],
        #   k12                     k13                     k14                     k15
            correct_column_3[0],    correct_column_0[3],    correct_column_1[1],    correct_column_2[0],
        ]    
        
        return key
