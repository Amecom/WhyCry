# WhyCry
# Copyright 2017 Amedeo Celletti
# http://www.amedeocelletti.com
"""
WhyCry symmetric key cryptography algorithms
"""
__version__ = '1.0.0'
__author__ = 'Amedeo Celletti'
__license__ = ''
__all__ = ['WhyCry']

from random import random
from hashlib  import sha512
from secrets import randbelow
from operator import add, sub

SPACE = " "
NUM = "0123456789"
HEX = NUM + "abcdef"
ALPHANUM = HEX + "ghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
ASCII_NOSPACE = ALPHANUM + "!\"#$%&'()*+,-./:;<=>?@[\]^_`{|}~"
ASCII = SPACE + ASCII_NOSPACE
ASCIIEXT_NOSPACE = ASCII_NOSPACE + "€‚ƒ„…†‡ˆ‰Š‹ŒŽ‘’“”•–—˜™š›œžŸ¡¢£¤¥¦§¨©ª«¬®¯°±²³´µ¶·¸¹º»¼½¾¿ÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏÐÑÒÓÔÕÖ×ØÙÚÛÜÝÞßàáâãäåæçèéêëìíîïðñòóôõö÷øùúûüýþÿ"
ASCIIEXT = SPACE + ASCIIEXT_NOSPACE
MAIL = "abcdefghijklmnopqrstuvwxyz0123456789@.-_+"

class WhyCry:

    # COMMON DICTIONARY
    DIZ = {
        'num' : NUM,
        'hex' : HEX,
        'alphanum' : ALPHANUM,
        'ascii_nospace' : ASCII_NOSPACE,
        'ascii' : ASCII,
        'asciiext_nospace': ASCIIEXT_NOSPACE,
        'asciiext': ASCIIEXT,
        'mail': MAIL
    }

    @staticmethod
    def token(dictionary, length:int) -> str:
        """Create a string useful to generate secretkey for a 'dictionary'."""
        d = WhyCry.DIZ[dictionary]
        n = len(d)
        return ''.join((d[randbelow(n)] for x in range(length)))

    def __init__(self, dictionary:str, secretkey:str):
        """
        'dictionary' is a string that must contains all possible character in 
        string to encode and secretskey.

        'secretkey' is the string used to encode/decode a text.
        Different secret key return different encode results.

        Different 'dictionary' string or
        characters order in 'dictionary' string or
        secretkey returns different encode results.
        
        Encode/decode function or initalize class
        raise en error if in secretkey or text
        to encode contains characters not in dictionary.
        """
        self.dictionary = WhyCry.DIZ[dictionary]
        self.secretkey = self._build_input(secretkey)
        self.signature = None

    def _build_input(self, string:str) -> [int]:
        f = self.dictionary.index
        return [f(char) for char in string]

    def _translate(self, mode:bool) -> None:
        t = self.text
        s = self.secretkey
        d = len(self.dictionary)
        r = len(t) // len(s) + 1
        if mode:
            self.text = [x if x < d else x - d for x in map(add, t, s * r)] 
        else:
            self.text = [x if x > -1 else x + d for x in map(sub, t, s * r)] 

    def _wide(self, mode:bool, lenght:int=0) -> None:
        t = self.text
        if mode:
            r = random
            t.insert(0, t[0])
            t.append(t[-1])
            cadd = lenght - len(t)
            cside = int(r() * cadd)
            max = len(self.dictionary) - 1
            for s in (cside, cadd - cside):
                for _ in range(s):
                    c1 = c2 = t[-1]
                    while c1 == c2:
                        c1 = int(r() * max)
                    t.append(c1)
                t.reverse()
        else:
            for m in range(2):
                for x in range(len(t) - 1):
                    if t[x] == t[x + 1]:
                        t = t[x + 1:]
                        break
                else:
                    # Impossible!  Invalid secretkey or dictionary
                    self.text = []
                    return
                t.reverse()
            # 't' is not more self.text after slice!
            self.text = t

    def _output(self) -> str:
        f = self.dictionary
        return ''.join([f[x] for x in self.text])

    def _sign(self, s:str) -> str:
        m = sha512()
        m.update(s.encode('utf-8'))
        return m.hexdigest()

    def encode(self, text:str, mode:bool=1, create_signature:bool=0) -> str:
        """Encode 'text' with dictonary and secrectkey set at initialization.

        Return text encoded.
        This function is reversible using decode function.

        If 'create_signature' after call function a class property
        call 'signature' is available. 

        Signature can be used to verify that decode function return
        a valid string.
        """
        self.text = self._build_input(text)
        self._translate(mode)
        if create_signature:
            self.signature = self._sign(text)
        return self._output()
           
    def decode(self, text:str) -> str:
        """Reverse encode function.

        Return original 'text' if is valid secretkey and dictionary.
        Return ALWAYS A STRING THOUGH secretkey or dictionary are WRONG. 
        """
        return self.encode(text, mode=0)

    def wencode(self, text:str, lenght:int, create_signature:bool=0) -> str:
        """Encode 'text' with dictonary and secrectkey set at initialization.

        Return a encode string with fixed 'lenght'.
        It applies a strong encryption adding disturbance characters to 'text'. 

        This function is reversible using wdecode function.

        'length' must be at least > len(text)+2

        If 'create_signature' after call function a class property
        call 'signature' is available. 

        """
        assert lenght > len(text) + 2, "Length must be at least >= len(text)+2" 
        self.text = self._build_input(text)
        self._wide(1, lenght)
        self._translate(1)
        if create_signature:
            self.signature = self._sign(text)
        return self._output()
           
    def wdecode(self, text:str) -> str:
        """Reverse a wencode function and Return original 'text'.

        Return ALWAYS A STRING THOUGH secretkey or dictionary are WRONG. 
        In some error cases can return an empty string.
        """
        self.text = self._build_input(text)
        self._translate(0)
        self._wide(0)
        return self._output()

    def verify(self, signature:str) -> bool:
        """Verify if decoded string is valid usign signature string.

        Return Bool
        A signature can be request when use encode function.
        """
        return signature == self._sign(self._output())


if __name__ == "__main__":

    def test(n, show_output):

        for dictionary in WhyCry.DIZ:

            for n in range(n+1):

                for ken_len in range(2):

                    secretkey = WhyCry.token(dictionary, len(WhyCry.DIZ[dictionary]) * 2)

                    # test with text logenr or shorter respect secretkey
                    if ken_len:
                        t0_len = len(secretkey) * 2
                    else:
                        t0_len = len(secretkey) // 2 + 3

                    t0 = WhyCry.token(dictionary, t0_len)
                    c = WhyCry(dictionary, secretkey)

                    #encode
                    t1 = c.encode(t0, create_signature=True)
                    sign = c.signature
                    t2 = c.decode(t1)
                    result_1 = t0 == t2
                    result_2 = c.verify(sign)

                    error = not (result_1 and result_2)

                    if error or show_output:
                        print("")
                        print("." * 100)
                        print("")
                        print("ENCODE / DECODE")
                        print("\nDICTIONARY:", dictionary)
                        print("\nSECRETKEY:", secretkey)
                        print("\nTEXT:", t0)
                        print("\nENCODE TEXT:", t1)
                        print("\nSIGNATURE:", sign)
                        print("\nDECODE:", t2)
                        print("\nEQUALITY:", result_1)
                        print("\nSIGNATURE VERIFY:", result_2)
                        if error:
                            raise "ERROR"

                    # wencode
                    w_len = len(t0) * 3
                    t1 = c.wencode(t0, w_len, create_signature=True)
                    sign = c.signature
                    t2 = c.wdecode(t1)
                    result_1 = t0 == t2
                    result_2 = c.verify(sign)
                    result_len = w_len = len(t1)

                    error = not (result_1 and result_2 and result_len)
                    if error or show_output:
                        print("")
                        print("." * 100)
                        print("")
                        print("WENCODE / WDECODE ")
                        print("\nDICTIONARY:", dictionary)
                        print("\nSECRETKEY:", secretkey)
                        print("\nTEXT:", t0)
                        print("\nWENCODE TEXT:", t1)
                        print("\nSIGNATURE:", sign)
                        print("\nWDECODE:", t2)
                        print("\nEQUALITY:", result_1)
                        print("\nSIGNATURE VERIFY:", result_2)
                        print("\nLEN CONFORMITY:", result_len)
                        if error:
                            raise "ERROR"

        print("OK")

    ntest = int(input("Number of test [number]?"))
    show_output = input("Show output [y/n]?") == "y"
    import timeit
    print("wait...")
    print(timeit.timeit('test({},{})'.format(ntest,show_output), setup="from __main__ import test", number=1))
