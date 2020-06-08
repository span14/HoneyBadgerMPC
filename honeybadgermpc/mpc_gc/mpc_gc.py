import sys
sys.path += ['elliptic-curves-finite-fields']
import os
import json
import gevent
import random
import secretsharing
from secretsharing import Fp, Poly
from finitefield.modp import IntegersModP
from collections import defaultdict
from Crypto.Hash import SHA256
from Crypto.Util.strxor import strxor
from gevent.event import AsyncResult

MODR = IntegersModP(0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001)
KEYLENGTH = 8

def NAND(a, b):
    if a == 1 and b == 1:
        return 0
    else:
        return 1

def XOR(a, b):
    if a == 1 and b == 1:
        return 0
    elif a == 1 or b == 1:
        return 1
    else:
        return 0

def AND(a, b):
    return a & b 

def OR(a, b):
    return a | b

GateMap = {
    "NAND": NAND,
    "XOR": XOR,
    "AND": AND,
    "OR": OR
}

# TODO: no handling for long share
def XOR_ENC(share, key1, key2):
    share_hex = hex(int(share))[2:]
    if len(share_hex) < len(key1):
        share_hex = share_hex.zfill(len(key1))
    byte_share = bytes.fromhex(share_hex)
    byte_key1 = bytes.fromhex(key1)
    byte_key2 = bytes.fromhex(key2)
    return strxor(strxor(byte_share, byte_key1), byte_key2).hex()

def XOR_DEC(enc, key1, key2):
    byte_share = bytes.fromhex(enc)
    byte_key1 = bytes.fromhex(key1)
    byte_key2 = bytes.fromhex(key2)
    return strxor(strxor(byte_share, byte_key1), byte_key2).hex()


class MPCSimulation():

    def __init__(self, n, cir, n_input, prog):
        # print("Running MPC in Constant Round of GC with n:", n, "cir:", cir)
        self.nodes = []
        self.n = n
        self.cir = cir
        self.prog = prog
        self.n_input = n_input
        self.keys = {}
        self.masks =  {}
        self.func_table = {}
        self.received_shares = {}
        
        self._create_random()
        self._create_function_table()
        self._create_share()
        self._create_public_output()

        self.received_shares = defaultdict(lambda: [AsyncResult() for _ in range(self.n)])

        def make_send_share(i):
            shareid=[0]
            def _send_share(share):
                self.received_shares[shareid[0]][i].set(share)
                shareid[0] += 1
            return _send_share
        
        def make_wait_for_shares(i):
            shareid=[0]
            def _wait_for_shares():
                shares = [self.received_shares[shareid[0]][j].get() for j in range(n)]
                shareid[0] += 1 
                return shares
            return _wait_for_shares

        # assume every one wants to know the output
        for i in range(n):
            send_share=make_send_share(i)
            wait_for_shares = make_wait_for_shares(i)
            gate_shares = {}
            for g, shares in self.poly_table.items():
                gate_shares[g] = []
                for share in shares:
                    gate_shares[g].append(share(Poly.field(i+1)))
            private_output = {
                "k": dict((w, (self.keys[w][0][i], self.keys[w][1][i])) for w in cir["wires"]),
                "g": gate_shares,
                "w": dict((ow, self.masks[ow]) for ow in cir["output"]),
            }
            node = MPCNode(n, 0, i, cir, wait_for_shares, send_share, self.public_out, private_output, prog)
            self.nodes.append(node)


    def _create_random(self):
        for w in self.cir['wires']:
            self.masks[w] = random.randint(0, 1)
            self.keys[w] = [[], []]
            for _ in range(self.n):
                self.keys[w][0].append(os.urandom(KEYLENGTH).hex())
                self.keys[w][1].append(os.urandom(KEYLENGTH).hex())

    def _create_function_table(self):
        def _generate_mask_func(x, y, ma, mb, mr, gf):
            return XOR(GateMap[gf](XOR(x, ma), XOR(y, mb)), mr)

        for g, g_content in self.cir['gates'].items():
            self.func_table[g] = []
            for i in range(4):
                x = int(i / 2)
                y = i % 2 
                z = _generate_mask_func(x, y, self.masks[g_content['i'][0]],self.masks[g_content['i'][1]], self.masks[g_content['o']], g_content['func'])
                self.func_table[g].append(
                    "".join(self.keys[g_content['o']][z])+str(z)
                )
        print(self.func_table)
    
    def _create_share(self):
        self.poly_table = {}
        for g, _ in self.cir['gates'].items(): 
            self.poly_table[g] = []
            for item in self.func_table[g]:
                # print(item)
                # print(int(item, 16))
                # test = Poly.random_with_intercept(Fp(int(item, 16)), self.n)
                # # print(test(Poly.field(0)))
                self.poly_table[g].append(
                    Poly.random_with_intercept(Fp(int(item, 16)), self.n-1)
                )
                
                # print("output map", int(item, 16))
    
    def _create_public_output(self):
        self.public_out = {}
        for g, g_content in self.cir['gates'].items():
            self.public_out[g] = []
            for inp in g_content["i"]:
                z = XOR(self.n_input[inp], self.masks[inp])
                self.public_out[g].append((
                    z,
                    self.keys[inp][z]
                ))
    
    def run(self):
        threads = [n._run() for n in self.nodes]
        gevent.joinall(threads)
        results = [t.get() for t in threads]
        # print(results)
        return results

class MPCNode():

    def __init__(self, n, f, myid, cir, wait_for_shares, 
                 send_share, public_output, private_output, prog):

        self.n = n
        self.myid = myid
        self.f = f
        self.cir = cir
        self._prog = prog
        self._wait_for_shares = wait_for_shares
        self._send_share = send_share
        self.public_output = public_output
        self._private_output = private_output
        self.encrypt_gate()
        
    
    def _run(self):
        self._thread = gevent.spawn(self._prog, self)
        return self._thread
    
    def encrypt_gate(self):
        self._encrypted_share = {}
        for g, g_shares in self._private_output["g"].items():
            # print(g_shares)
            self._encrypted_share[g] = []
            for i in range(4):
                # print(hex(int(g_shares[i]))[2:])
                x = int(i / 2) 
                y = i % 2
                kx = self._private_output["k"][self.cir["gates"][g]["i"][0]][x]
                ky = self._private_output["k"][self.cir["gates"][g]["i"][1]][y]
                hkx = SHA256.new(bytes.fromhex(kx)).hexdigest()
                hky = SHA256.new(bytes.fromhex(ky)).hexdigest()
                self._encrypted_share[g].append(XOR_ENC(g_shares[i], hkx, hky))
        # print("done: ", self.myid)
    
    def decode_shares(self, g, encrypt_gate):
        self._send_share(encrypt_gate)
        encrypt_gates = self._wait_for_shares()
        shares = []
        for i in range(self.n):
            eg = encrypt_gates[i]
            idx = self.public_output[g][0][0]
            idy = self.public_output[g][1][0]
            ids = idx * 2 + idy
            kx = self.public_output[g][0][1][i]
            ky = self.public_output[g][1][1][i]
            hkx = SHA256.new(bytes.fromhex(kx)).hexdigest()
            hky = SHA256.new(bytes.fromhex(ky)).hexdigest()
            # print(XOR_DEC(eg[ids], hkx, hky).lstrip("0"))
            share = int(XOR_DEC(eg[ids], hkx, hky).lstrip("0"), 16)
            shares.append(MODR(share))
        shares = [(Fp(i+1), share) for i, share in enumerate(shares)]
        # print(shares)
        return secretsharing.decode_shares(self.n, self.f, shares)



# getting output of the circuit
def compute_single_NAND(context):
    r = context.decode_shares("g1", context._encrypted_share["g1"])
    print(hex(int(r))[-1])
    print(context._private_output["w"]["w3"])
    # print(context._private_output)
    o = XOR(int(hex(int(r))[-1]), context._private_output["w"]["w3"])
    print(o)
    assert o == 1
    # # return o

if __name__ == "__main__":
    try:
        single_NAND_file = open("test_circuit.json")
        single_NAND = json.load(single_NAND_file)
        MPCSimulation(3, single_NAND, {"w1": 0, "w2": 1}, compute_single_NAND).run()
    except Exception as e:
        print(e)


