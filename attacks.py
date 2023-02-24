import time
import argparse
from os import path
import copy
from aes.test_key import test_key

# DTA
from rsa_dta import dta

# DPA
from aes_dpa import dpa
from aes_dpa.plot import plot_trace

# DFA
from aes_dfa import dfa

DTA_STR = 'dta'
DPA_STR = 'dpa'
DFA_STR = 'dfa'


if __name__ == '__main__':
    description = """
A python script to perform some very basic physical attacks. There are 3 attacks implemented:
    - Differential Timing Attack (DTA) on RSA
    - Differential Power Analysis (DPA) on AES
    - Differential Fault Attack (DFA) on AES
    
Chose an attack and either provide your own input data, or use the provided example data.
    """
    parser = argparse.ArgumentParser(description=description, formatter_class=argparse.RawTextHelpFormatter)
    
    parser.add_argument('attack',
                        type=str,
                        choices=[DTA_STR, DPA_STR, DFA_STR],
                        help='The attack to perform. Choose from: dta, dpa, dfa')
    
    parser.add_argument('--input',
                        type=str,
                        help=   'Path to an input folder containing, e.g. traces for DPA. ' +
                                'Check the README for more information on, e.g. file names.')
    
    parser.add_argument('--plot-dpa',
                        action='store_true',
                        help='Whether to plot the power traces for DPA.')

    parser.add_argument('--save-plot',
                        action='store_true',
                        help='Whether to save the DPA plot.')
    
    args = parser.parse_args()
    
    if args.input and not path.exists(args.input):
        print("You need to provide a valid path to the input data.")
        quit()
    attack: str = args.attack
    input_path: str = args.input
    plot_dpa = args.plot_dpa
    save_plot = args.save_plot
    if save_plot and not plot_dpa:
        plot_dpa = True
    
    ############################### PERFORM DTA ####################################
    if attack == DTA_STR:
        dta_runner = dta.DTA(input_path)
        start = time.time()
        key = dta_runner.perform_timing_attack()
        consumed = time.time() - start

        # TEST RESULTS
        keyhex = ",".join(["%02X" % (key >> 64 - (8 * (i + 1)) & 0x00000000000000FF) for i in range(8)])
        with open("rsa_dta/input_files/correct_key.txt", "r") as sol:
            expected = sol.read()
            if expected == keyhex:
                print("Congratulations! Your attack works")
                result = True
            else:
                print(":( Your attack is not working yet. Keep on trying!")
                print("Expected:", expected)
        print("Your key:", keyhex)
        print("Attack time [s]: {:.3f}".format(consumed))
    
    ############################### PERFORM DPA ####################################
    if attack == DPA_STR:
        dpa_runner = dpa.DPA(input_path)
        t = time.perf_counter()
        last_round_key = dpa_runner.perform_dpa()
        consumed = time.perf_counter() - t

        # TEST RESULTS
        result, key = test_key(last_round_key, dpa_runner.reader.plaintexts[0], dpa_runner.reader.ciphertexts[0])
        if result:    
            print(f"Congratulations! Your key {key} is right.")
        else:
            print("Your key is wrong, AES is too strong. Just go on, it won't take that long")
        print("Attack time [s]: {:.3f}".format(consumed))
        
        if plot_dpa:
            plot_trace(input_path, save_plot)
            
    ############################### PERFORM DFA ####################################
    if attack == DFA_STR:
        dfa_runner = dfa.DFA(input_path)
        # Save one cipher/plaintext pair in case the input lists get modified inplace
        test_plain = copy.copy(dfa_runner.reader.plaintexts[0])
        test_cipher = copy.copy(dfa_runner.reader.ciphertexts[0])
        
        t = time.perf_counter()
        last_round_key = dfa_runner.perform_dfa()
        consumed = time.perf_counter() - t

        # TEST RESULTS
        result, key = test_key(last_round_key, dfa_runner.reader.plaintexts[0], dfa_runner.reader.ciphertexts[0])
        if result:
            print("Congratulations! Your key is correct.")
        else:
            print("Not only the ciphertexts are faulty, your key is too.")
        print("Key guess: " + key)
        print("Attack time [s]: {:.3f}".format(consumed))
