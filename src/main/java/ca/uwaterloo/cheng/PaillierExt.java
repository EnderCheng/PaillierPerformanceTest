package ca.uwaterloo.cheng;

import java.math.BigInteger;
import java.security.SecureRandom;

public class PaillierExt {
    /**
     * p and q are two large primes.
     * lambda = lcm(p-1, q-1) = (p-1)*(q-1)/gcd(p-1, q-1).
     */
    private BigInteger p,  q,  lambda;
    private SecureRandom rnd = new SecureRandom();
    /**
     * n = p*q, where p and q are two large primes.
     */
    public BigInteger n, n_half;
    /**
     * nsquare = n*n
     */
    public BigInteger nsquare;
    /**
     * a random integer in Z*_{n^2} where gcd (L(g^lambda mod n^2), n) = 1.
     */
    private BigInteger g;
    /**
     * number of bits of modulus
     */
    private int bitLength;

    /**
     * Constructs an instance of the Paillier cryptosystem.
     * @param bitLengthVal number of bits of modulus
     * @param certainty The probability that the new BigInteger represents a prime number will exceed (1 - 2^(-certainty)). The execution time of this constructor is proportional to the value of this parameter.
     */
    public PaillierExt(int bitLengthVal, int certainty) {
        KeyGeneration(bitLengthVal, certainty);
    }

    /**
     * Constructs an instance of the Paillier cryptosystem with 512 bits of modulus and at least 1-2^(-64) certainty of primes generation.
     */
    public PaillierExt() {
        KeyGeneration(2048, 80);
    }

    public void KeyGeneration(int bitLengthVal, int certainty) {
        bitLength = bitLengthVal;
        /*Constructs two randomly generated positive BigIntegers that are probably prime, with the specified bitLength and certainty.*/
        p = new BigInteger(bitLength / 2, certainty, rnd);
        q = new BigInteger(bitLength / 2, certainty, rnd);

        n = p.multiply(q);
        nsquare = n.multiply(n);
        n_half = n.divide(BigInteger.TWO);
        g = n.add(BigInteger.ONE);
        lambda = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE)).divide(
                p.subtract(BigInteger.ONE).gcd(q.subtract(BigInteger.ONE)));
    }


    public BigInteger Encryption(BigInteger m) {
        BigInteger r = new BigInteger(bitLength, rnd);
        if(m.signum() == -1)
        {
            m = n.add(m);
        }
        return (BigInteger.ONE.add(m.multiply(n))).multiply(r.modPow(n, nsquare)).mod(nsquare);
    }

    /**
     * Decrypts ciphertext c. plaintext m = L(c^lambda mod n^2) * u mod n, where u = (L(g^lambda mod n^2))^(-1) mod n.
     * @param c ciphertext as a BigInteger
     * @return plaintext as a BigInteger
     */
    public BigInteger Decryption(BigInteger c) {
        BigInteger u = g.modPow(lambda, nsquare).subtract(BigInteger.ONE).divide(n).modInverse(n);
        BigInteger tmp = c.modPow(lambda, nsquare).subtract(BigInteger.ONE).divide(n).multiply(u).mod(n);
        return tmp.add(n_half).mod(n).subtract(n_half);
//        if(tmp.compareTo(n_half) == 1)
//        {
//            return tmp.subtract(n);
//        }
//        return tmp;
    }

    /**
     * main function
     * @param str intput string
     */
    public static void main(String[] str) {
        /* instantiating an object of Paillier cryptosystem*/
        long start, end;
        PaillierExt paillier = new PaillierExt();
        /* instantiating two plaintext msgs*/
        BigInteger m1 = BigInteger.valueOf(-2000000000L);
        BigInteger m2 = BigInteger.valueOf(-6000000000L);
        /* encryption*/
        start = System.nanoTime();
        BigInteger em1 = paillier.Encryption(m1);
        end = System.nanoTime();
        System.out.println("encryption:"+ (end-start));
        BigInteger em2 = paillier.Encryption(m2);
        /* printout encrypted text*/
        System.out.println(em1);
        System.out.println(em2);
        /* printout decrypted text */
        System.out.println(paillier.Decryption(em1).toString());
        start = System.nanoTime();
        System.out.println(paillier.Decryption(em2).toString());
        end = System.nanoTime();
        System.out.println("decryption:"+ (end-start));

        /* test homomorphic properties -> D(E(m1)*E(m2) mod n^2) = (m1 + m2) mod n */
        start = System.nanoTime();
        BigInteger product_em1em2 = em1.multiply(em2).mod(paillier.nsquare);
        end = System.nanoTime();
        System.out.println("ciphertext + ciphertext:"+ (end-start));
        BigInteger sum_m1m2 = m1.add(m2);
        System.out.println("original sum: " + sum_m1m2);
        System.out.println("decrypted sum: " + paillier.Decryption(product_em1em2));

        /* test homomorphic properties -> D(E(m1)^m2 mod n^2) = (m1*m2) mod n */
        start = System.nanoTime();
        BigInteger expo_em1m2 = em2.modPow(m1, paillier.nsquare);
        end = System.nanoTime();
        System.out.println("plaintext * ciphertext:"+ (end-start));
        BigInteger prod_m1m2 = m1.multiply(m2);
        System.out.println("original product: " + prod_m1m2);
        System.out.println("decrypted product: " + paillier.Decryption(expo_em1m2));

        BigInteger em3 = em2.modPow(BigInteger.ONE.negate(),paillier.nsquare);
        System.out.println(paillier.Decryption(em3));



    }
}
