# Some Physical Attacks

- [Introduction](#introduction)
- [Preconditions](#preconditions)
- [Timing Attack on RSA](#timing-attack-on-rsa)
  - [Introduction \& Idea](#introduction--idea)
  - [Attack Principle](#attack-principle)
  - [How to run the attack](#how-to-run-the-attack)
- [Differential Power Analysis on AES](#differential-power-analysis-on-aes)
  - [Introduction \& Idea](#introduction--idea-1)
  - [Attack Principle](#attack-principle-1)

## Introduction
This repository contains some very simple, rather theoretical physical attacks, including a *Timing Attack* on RSA, *Differential Power Analysis* on AES and *Differential Fault Attack* also on AES. The attacks are implemented in Python and the code is well documented. The attacks are not optimized for speed, but are just my first attempts at implementing attacks like this. The attacks are not meant to be used in real life, but rather to illustrate the principles of the attacks, e.g. the timing attack on RSA only recovers 64b of the key (which is normally 1024b-4096b).

In the following sections I will briefly explain the theory behind the attacks and describe how they can be executed.

## Preconditions
There are a couple of standard python libraries in use. Install them by running the command: `pip install -r requirements.txt`.

## Timing Attack on RSA
### Introduction & Idea
This timing attack on RSA is based on the data dependent reduction in the (original) Montgomery Multiplication, which is used for modular multiplication in RSA:
```python
def MontgomeryMul(self, a: int, b: int, n: int, n1: int):
    """
    Montgomery Multiplication
    Returns: f=a*b and er=1 if reduction is done, er=0 otherwise
    """

    # Do some stuff
    if f >= n:
        er = 1
        f = f - n

    return f, er
```

Here, f is the result of the modular multiplication & as can be seen in the code snippet above, depending on the size of f, an extra reduction step is done. This reduction step is data dependent and takes a longer amount of time to compute. This can be exploited to recover the private key `d` in RSA by measuring the timing of the RSA computation. As already mentioned above, in this example, we only recover 64b of a key to prove the concept. 

### Attack Principle
The attack works as follows:
1. Compute the RSA ciphertext `c` for a lot of different messages and public key `e` and `n`. Measure the timings for all of these computations. In our example this has already been done, you can find the CSV files for the ciphertexts & timings under `rsa_dta/inputs`.
2. The first bit of the private key `d` will always be `1`, we can discard any leading `0`s.
3. Starting from the second bit of `d`, do the following:
   1. Propose 2 hypotheses for the currently attacked bit of `d`, which are `0` and `1`, resulting in `d0` and `d1`.
   2. For both hypotheses, compute the exponentiation `m^d0/1` using the `Left-to-Right-Square-And-Multiply` algorithm with the Montgomery Multiplication. This algorithm works by always squaring the message & multiplying it if the current bit is `1`. For the last Montgomery Multiplication, store, whether an extra reduction step was done or not. This step is revered to as *Look-Ahead*. We can improve this by storing the result of each exponentiation and reusing it for the next bit. This is not necessary but greatly improves the speed of the attack.
   3. After doing this for all ciphertexts, we have 2 lists for the extra reductions for both hypotheses.
   4. Finally we use the *Pearson Correlation Coefficient* to calculate the correlation of the extra reductions for both hypotheses with the timing data. The hypothesis with the highest correlation is the correct one. We set the bit of `d` to the correct hypothesis and continue with the next bit.
4. For the last bit we cannot do a *Look-Ahead*. Therefore we just need to manually test both possibilities to get the final bit of `d`.

### How to run the attack
You can run all of the attacks easily from one script.
1. Make sure you install the required libraries by running `pip install -r requirements.txt`.
2. Run the attack by executing: `python3 attacks.py dta`.

## Differential Power Analysis on AES
### Introduction & Idea
Differential Power Analysis (DPA) is a side channel attack usually used on cryptographic algorithms. It works by measuring the power consumption of the algorithm and correlating this power consumption with intermediate values calculated during the computation. With this correlation secret information can be extracted. In principle, the attack works on any algorithm, without specific knowledge of the algorithm. However, the number of required traces can be greatly decreased by cleverly using knowledge about the attacked algorithm. In this example, we will attack an AES algorithm in the last round, to extract the last round key, which can be used to calculate the AES master key.

### Attack Principle
For each byte of the last round key do the following:
1. Create a list of all 256 possible values for the byte.
2. Create the *V-Matrix* by calculating the inverse Sub-Bytes transformation for all key hypotheses & each column of our ciphertext:
  
```math
\qquad\qquad\qquad
K = \begin{bmatrix} 
k_{1} & \dots  & k_{K}
\end{bmatrix}
```

```math
\qquad\qquad\qquad\qquad
&darr;
```

```math
D = \begin{bmatrix} 
d_{1}\\
\vdots\\
d_{D} 
\end{bmatrix}
&rarr;
V = \begin{bmatrix} 
v_{11} & \dots  & v_{1K} \\
\vdots & \ddots & \vdots \\
v_{D1} & \dots & v_{DK} 
\end{bmatrix}
```

