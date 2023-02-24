import numpy as np
import h5py
import csv
import os

# path of the traces hdf5 file which will be used in the dpa analysis
DEFAULT_DPA_TRACES_PATH = 'aes_dpa/traces/sample_trace.h5'
DEFAULT_DTA_INPUT_PATH = 'rsa_dta/input_files'
DTA_INPUT_FILE = 'inputs.csv'
DTA_TIMING_FILE = 'timings.csv'
DTA_TESTING_PAIR_FILE = 'testing_pair.csv'
DEFAULT_DFA_INPUT_PATH = 'aes_dfa/faulty_pairs.csv'

class Reader:
    def __init__(self, input_path: str) -> None:
        if input_path:
            self.input_path = input_path
        else:
            self.input_path = self.default_input_path
        
    def __read_input_files(self):
        raise NotImplementedError
        
class DPAReader(Reader):
    """Class used to load traces measured with measuring script."""

    def __init__(self, input_path: str):
        self.default_input_path = DEFAULT_DPA_TRACES_PATH
        super().__init__(input_path)
        self.hdf5_file = h5py.File(self.input_path, "r")
        (self.traces, 
         self.ciphertexts, 
         self.plaintexts) = self.__read_input_files()
        
    def __read_input_files(self) -> 'tuple(list, list, list)':
        return self.__get_traces(), self.__get_ciphertext(), self.__get_plaintext()

    def __get_traces(self):
        """Returns measured traces in a matrix: trace-number x trace-length"""
        traces = self.hdf5_file["traces"][:].astype(np.int16)
        return traces

    def __get_ciphertext(self):
        """Returns ciphertexts in a matrix: trace-number x 16 bytes ciphertext"""
        return self.hdf5_file["ciphertext"][:].astype(np.uint8)

    def __get_plaintext(self):
        """Returns plaintexts in a matrix: trace-number x 16 bytes plaintext"""
        return self.hdf5_file["plaintext"][:].astype(np.uint8)
    
    def get_plaintext_column(self, number: int) -> list:
        """Get a specific column of plaintexts dataset.

        Args:
            number (int): Column number of plaintexts dataset.

        Returns:
            list: The desired column of plaintexts dataset.
        """
        return self.plaintexts[:,number].astype(np.uint8)

    def get_ciphertext_column(self, number: int) -> list:
        """Get a specific column of the ciphertexts dataset.

        Args:
            number (int): Column number of the ciphertexts dataset.

        Returns:
            list: The desired column of the ciphertexts dataset.
        """
        return self.ciphertexts[:,number].astype(np.uint8)
    
class DTAReader(Reader):
    def __init__(self, input_path: str) -> None:
        self.default_input_path = DEFAULT_DTA_INPUT_PATH
        super().__init__(input_path)
        (self.timings,
         self.testing_pair,
         self.inputs) = self.__read_input_files()
        
    def __read_input_files(self) -> 'tuple(list, list, list)':
        csv_reader = csv.reader(open(os.path.join(self.default_input_path, 
                                                  DTA_TIMING_FILE), 
                                     'r'), 
                                delimiter=',')
        timings = [int(element) for element in next(csv_reader)]
        csv_reader = csv.reader(open(os.path.join(DEFAULT_DTA_INPUT_PATH, 
                                                  DTA_TESTING_PAIR_FILE),
                                     'r'),
                                delimiter=',')
        testing_pair = [int(element) for element in next(csv_reader)]
        csv_reader = csv.reader(open(os.path.join(DEFAULT_DTA_INPUT_PATH,
                                                  DTA_INPUT_FILE),
                                     'r'),
                                delimiter=',')
        inputs = [int(element) for element in next(csv_reader)]
        
        return timings, testing_pair, inputs
    
class DFAReader(Reader):
    def __init__(self, input_path: str) -> None:
        self.default_input_path = DEFAULT_DFA_INPUT_PATH
        super().__init__(input_path)
        (self.plaintexts,
         self.ciphertexts,
         self.faulty_ciphertexts) = self.__read_input_files()
        
    def __read_input_files(self) -> 'tuple(list, list, list)':
        plaintexts = []
        ciphertexts = []
        faulty_ciphertexts = []
        csv_reader_faulty_pairs = csv.reader(
            open(self.input_path, 'r'), 
            delimiter=',')

        for row in csv_reader_faulty_pairs:
            plaintexts.append([int(row[0][i:i + 2], 16)
                            for i in range(2, len(row[0]), 2)])
            ciphertexts.append([int(row[1][i:i + 2], 16)
                                        for i in range(2, len(row[1]), 2)])
            faulty_ciphertexts.append([int(row[2][i:i + 2], 16)
                                    for i in range(2, len(row[2]), 2)])

        return plaintexts, ciphertexts, faulty_ciphertexts