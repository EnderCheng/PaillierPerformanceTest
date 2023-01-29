package ca.uwaterloo.cheng;

import java.math.BigInteger;
import java.security.SecureRandom;

public class PaillierExt {

    private BigInteger p,  q,  lambda;
    private SecureRandom rnd = new SecureRandom();

    public BigInteger n, n_half;

    public BigInteger n_square;

    private BigInteger g;

    private int bitLength;

    public PaillierExt(int bitLength, int certainty) {
        KeyGeneration(bitLength, certainty);
    }

    public PaillierExt() {
        KeyGeneration(2048, 80);
    }

    public void KeyGeneration(int bitLength, int certainty) {
        this.bitLength = bitLength;
        p = new BigInteger(bitLength / 2, certainty, rnd);
        q = new BigInteger(bitLength / 2, certainty, rnd);
        n = p.multiply(q);
        n_square = n.multiply(n);
        n_half = n.divide(BigInteger.TWO);
        g = n.add(BigInteger.ONE);
        lambda = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE)).divide(
                p.subtract(BigInteger.ONE).gcd(q.subtract(BigInteger.ONE)));
    }


    public BigInteger Encrypt(BigInteger m) {
        BigInteger r = new BigInteger(bitLength, rnd);
        return (BigInteger.ONE.add(m.multiply(n))).multiply(r.modPow(n, n_square)).mod(n_square);
    }

    public BigInteger Decrypt(BigInteger c) {
        BigInteger u = g.modPow(lambda, n_square).subtract(BigInteger.ONE).divide(n).modInverse(n);
        BigInteger tmp = c.modPow(lambda, n_square).subtract(BigInteger.ONE).divide(n).multiply(u).mod(n);
        return tmp.add(n_half).mod(n).subtract(n_half);
    }

    public static void main(String[] str) {
        PaillierExt PE = new PaillierExt();
        long start, end;

        BigInteger m = BigInteger.valueOf(-300);
        start = System.nanoTime();
        BigInteger c = PE.Encrypt(m);
        end = System.nanoTime();
        System.out.println("PaillierExt Encryption:"+ (end-start)/1000000.0);
        start = System.nanoTime();
        BigInteger d = PE.Decrypt(c);
        end = System.nanoTime();
        System.out.println("PaillierExt Decryption:"+ (end-start)/1000000.0);
        System.out.println(d);
    }
}
