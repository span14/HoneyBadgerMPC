"""
## Handout 1: Programming with Polynomials and Lagrange Interpolation
"""
import sys
sys.path += ['elliptic-curves-finite-fields']
from finitefield.finitefield import FiniteField
from finitefield.polynomial import polynomialsOver
from finitefield.euclidean import extendedEuclideanAlgorithm
from finitefield.modp import IntegersModP
from elliptic import EllipticCurve, Point, Ideal
import elliptic
import os
import random
from polynomials import polynomialsOver, eval_poly, interpolate
from prime_mod_sqrt import prime_mod_sqrt

# Parameters for MPC
# We make use of a field Fp() that is a large prime number
Fp = FiniteField(0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001,1)
Poly = polynomialsOver(Fp)

# For convenience, upgrade the polynomial class with static methods.
# If f is a Poly, then you can call f(x) to evaluate the polynomial
Poly.__call__ = eval_poly
Poly.interpolate = staticmethod(lambda *args, **kwargs: interpolate(Poly, *args, **kwargs))

"""
## Generate a random polynomial with a given degree
"""
def random_poly_with_intercept(Poly, s, k):
    # Returns a degree-k polynomial f
    # such that f(0) = s
    coeffs = [None] * (k+1)
    coeffs[0] = Poly.field(s)
    for i in range(1,k+1):
        coeffs[i] = Poly.field(random.randint(0,Poly.field.p-1))
    return Poly(coeffs)
Poly.random_with_intercept = staticmethod(lambda *args, **kwargs: random_poly_with_intercept(Poly, *args, **kwargs))



#########################
# Shamir's Secret Sharing
#########################

def create_secret_share(n, f, s):
    assert type(f) is type(n) is int
    assert 2 <= f <= n

    # Encode the secret as a random degree-f polynomial phi
    phi = Poly.random_with_intercept(s, f)
    print ("Secret sharing s=", s, "degree f=", f)
    print ("The secret value is phi(0) = ", phi(Poly.field(0)))
    print ("The polynomial is:", phi)

    s = [None] * n
    for i in range(n):
        s[i] = (i+1, phi(Poly.field(i+1)))
        print ("(%d, phi(%d) = %s)" % (i+1, i+1, s[i][1]))
    return s

def decode_shares(n, f, shares, Poly=Poly):
    n = len(shares)
    xs = [share[0] for share in shares]

    # Use interpolation to recover the
    # entire polynomial phi
    phi = interpolate(Poly, shares)
    
    # Evaluate phi at x=0 to recover the original secret
    return phi(0)

if __name__ == '__main__':
    point_to_encode = Fp(88215013034249605347380387511226531006983076281096838730960)
    n = 5
    f = 2
    shares = create_secret_share(n, f, point_to_encode)
    # shares = [(share[0], IntegersModP(0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001)(int(share[1]))) for share in shares]
    recomb = decode_shares(n, f, shares)
    print ('point_to_encode:', point_to_encode)
    print ('shares:', shares)
    print ('recomb:', recomb)
    print(shares[0][1])
    print(int(shares[0][1]))
    print(type(IntegersModP(0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001)(int(shares[0][1]))))

    print("Another Test: ")
    secrets = ['e0dafb5bcfef6313e586aef2b682652f489c23c595be254d0', 'e0dafb5bcfef6313e586aef2b682652f489c23c595be254d0', 'e0dafb5bcfef6313e586aef2b682652f489c23c595be254d0', 'b0d1d19582411b6eab2c66e762f73ac74f0e69ed11969ba41']
    shares = []
    for secret in secrets:
        phi = Poly.random_with_intercept(Fp(int(secret, 16)), 2)
        # print("phi = ", phi)
        share = []
        for i in range(3):
            share.append(phi(Poly.field(i+1)))
        shares.append(share)
        # shares.append(create_secret_share(3, 2, Fp(int(secret, 16))))
    outputs = []
    for share in shares:
        # print("Shares: ", [(i+1, t) for i, t in enumerate(share)])
        outputs.append(decode_shares(3, 0, [(Fp(i+1), t) for i, t in enumerate(share)]))
        # outputs.append(decode_shares(2, 2, share))
    print("Secret in int: ", [int(secret, 16) for secret in secrets])
    print("Recomb outputs: ", outputs)
    

######################################
# Problem 3.1: Decoding with erasures   [5pts]
######################################

# Note: If you go straight to 3.2, you do not
# also have to complete this one. You can just
# define `decode_with_errors` to get the points
# for this one too.

    
"""
## Decoding with erasures
"""
def decode_with_erasures(n, f, shares_or_erasures, Poly=Poly):
    f = Poly([0])
    # TODO: Your code goes here
    samples = []
    counter = 0
    for share in shares_or_erasures:
        if share != None:
            samples.append(share)
            counter += 1
        if counter >= f+1:
            break
    
    f = interpolate(Poly, samples)
    return f(0)

    
######################################
# Problem 3.2: Decoding with errors    [5pts]
######################################

def decode_with_errors(n, f, shares_or_erasures):
    # Attempt to interpolate with any subset of f+1 values.
    # If the resulting polynomial coincides with 2f+1 values,
    # then at least f+1 of these must be honest (by assumption).
    # Since a degree-f polynomial is determined by f+1 points,
    # this guarantees the resulting polynomial is correct

    # If we detect at least one error, it is still possible we
    # can recover. We can simply try random subsets of f+1 values
    # until we find one that works. However, this will not be efficient
    # when n gets larger and larger

    # TODO: Your code goes here
    while True:
        sample_points = random.sample(shares_or_erasures, k=f+1)
        if None in sample_points:
            continue
        
        phi = Poly.interpolate(sample_points)
        counter = f+1
        for share in shares_or_erasures:
            if share in sample_points or share == None:
                continue
            if share[1] == Fp(phi(share[0])):
                counter += 1
        if counter >= 2*f+1:
            return phi(Fp(0))
