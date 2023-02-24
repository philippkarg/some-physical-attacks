######################## IMPORT MODULES #############################
import numpy as np
import reader as rd
###################### USEFUL ROUTINES ##############################

class DTA:
    
    def __init__(self, input_path: str):
        self.reader = rd.DTAReader(input_path)

    @staticmethod
    def testBit(val, offset):
        """
        Test whether bit at position offset is set or not
        Returns: 1 if it is set, 0 otherwise
        """
        if (val & (1 << offset)) != 0:
            return bool(1)
        else:
            return bool(0)

    @staticmethod
    def testPair(testing_pair, d, n):
        """
        Test whether the provided secret key d is correct or not
        Returns: 1 if it is correct, 0 otherwise
        """
        y = testing_pair[0]
        S = testing_pair[1]

        S1 = int(pow(y, d, n))

        if S == S1:
            return bool(1)
        else:
            return bool(0)


    def extEuclideanAlg(self, a, b):
        """
        Extended Euclidean algorithm
        """
        if b == 0:
            return 1, 0, a
        else:
            x, y, gcd = self.extEuclideanAlg(b, a % b)
            return y, x - y * (a // b), gcd


    def modInvEuclid(self, a, n):
        """
        Computes the modular multiplicative inverse using
        the extended Euclidean algorithm
        Returns: multiplicative inverse of a modulo n
        """
        x, y, gcd = self.extEuclideanAlg(a, n)
        if gcd == 1:
            return x % n
        else:
            return None


    def MontgomeryMul(self, a: int, b: int, n: int, n1: int):
        """
        Montgomery Multiplication
        Returns: f=a*b and er=1 if reduction is done, er=0 otherwise
        """

        # ... WRITE YOUR CODE HERE ...
        er = 0
        # Create a mask to get the lower n bits
        # In our case the mask is 0xFFFFFFFFFFFFFFFF
        mask = (1 << n.bit_length()) - 1
        c = a * b
        # Use the mask to get the lower n bits
        d = ((c & mask) * n1) & mask
        e = c + d * n
        f = e >> n.bit_length()
        if f >= n:
            er = 1
            f = f - n

        return f, er

    def look_ahead(self, m: int, d: int, n: int, n1: int, s1: int, z2: int):
        m1 = self.MontgomeryMul(m, z2, n, n1)[0]
        er = 0
        # Since we saved the signatures from previous iterations,
        # we only need to calculate the last step.
        if self.testBit(d, 0):
            s1 = self.MontgomeryMul(s1, m1, n, n1)[0]
        s1, er = self.MontgomeryMul(s1,s1, n, n1)
        
        return s1, er

    def perform_timing_attack(self):
        """
        Timing attack
        Returns: Secret key d (64 bit integer number)
        """

        n = int(0xB935E2B84B83E9EB)  # modulus
        z = int(pow(2, 64))
        z2 = int(pow(z, 2, n))
        n1 = self.modInvEuclid(-n, z)
        
        d = int(0)
        
        # Set key to 1, since we know that the first bit has to be 1
        d = 1
        
        # List for storing the extra reductions & updated signatures
        extra_reductions_0 = []
        extra_reductions_1 = []
        signatures_0 = []
        signatures_1 = []
        signatures = self.reader.inputs.copy()
        
        # Square & Multiply the input messages once
        signatures = [self.look_ahead(sig, d, n, n1, z, z2)[0] for sig in signatures]
        # Key extraction for bits 1 to 62
        for i in range(1, 63):
            # Key Hypotheses for the next bit
            d_0 = d << 1
            d_1 = (d << 1) | 1
            
            # Calculate the extra reductions for both hypotheses
            # Store the signatures in temporary lists, so that we
            # can copy the correct list to the signatures list.
            # Copying the signatures, instead of re-calculating them
            # saves a lot of time. 
            for input, signature in zip(self.reader.inputs, signatures):
                s_0, e_0 = self.look_ahead(input, d_0, n, n1, signature, z2)
                signatures_0.append(s_0)
                extra_reductions_0.append(e_0)
                s_1, e_1 = self.look_ahead(input, d_1, n, n1, signature, z2)
                signatures_1.append(s_1)
                extra_reductions_1.append(e_1)
                
            # Compare the correlation coefficients of the timings and the extra reductions
            # Chose the one with the higher correlation coefficient.
            if abs(np.corrcoef(self.reader.timings, extra_reductions_0)[0,1]) < abs(np.corrcoef(self.reader.timings, extra_reductions_1)[0,1]):
                d = d_1 
                signatures = signatures_1.copy()
            else:
                d = d_0
                signatures = signatures_0.copy()
            
            # Print the current key byte
            if i % 4 == 3:
                print(hex(d)[2:].upper(), end="\r")
            
            # Reset
            extra_reductions_0.clear()
            extra_reductions_1.clear()
            signatures_0.clear()
            signatures_1.clear()
        
        # Test the last bit
        d_0 = d << 1
        d_1 = (d << 1) | 1
        if self.testPair(self.reader.testing_pair, d_0, n):
            d = d_0
        else:
            d = d_1
        # Make sure that the secret key is correct
        assert(self.testPair(self.reader.testing_pair, d, n))
        
        return d


