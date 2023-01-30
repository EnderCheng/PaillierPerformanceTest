package ca.uwaterloo.cheng;

import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.RunnerException;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.concurrent.TimeUnit;


public class PaillierOpt {
    private BigInteger P,Q, p, q, p_pri, q_pri, tau, xi, two_tau, two_tau_inv;
    private SecureRandom rnd = new SecureRandom();
    public BigInteger N, N_half;
    public BigInteger N_square;
    private BigInteger g;
    private int  k, kappa;

    public PaillierOpt()
    {
        this.k = 2048;
        this.kappa = 448;
        KeyGeneration(80);
    }

    public PaillierOpt(int bitLength, int kappa){
        this.k = bitLength;
        this.kappa = kappa;
        KeyGeneration(80);
    }

    public void KeyGeneration(int certainty) {
        do {
            p_pri = new BigInteger((k - kappa) / 2 - 1, rnd);
            q_pri = new BigInteger((k - kappa) / 2 - 1, rnd);
        } while (!p_pri.testBit(0) || !q_pri.testBit(0) || q_pri.gcd(p_pri).compareTo(BigInteger.ONE) != 0);

        do {
            p = new BigInteger(kappa / 2, certainty, rnd);
            P = p_pri.multiply(p).multiply(BigInteger.TWO).add(BigInteger.ONE);
        } while (!P.isProbablePrime(certainty) || p.gcd(p_pri).compareTo(BigInteger.ONE) != 0 ||
                p.gcd(q_pri).compareTo(BigInteger.ONE) != 0);
        do {
            q = new BigInteger(kappa / 2, certainty, rnd);
            Q = q_pri.multiply(q).multiply(BigInteger.TWO).add(BigInteger.ONE);
        } while (!Q.isProbablePrime(certainty) || q.gcd(p_pri).compareTo(BigInteger.ONE) != 0 ||
                q.gcd(q_pri).compareTo(BigInteger.ONE) != 0);

        N = P.multiply(Q);
        N_square = N.multiply(N);
        N_half = N.divide(BigInteger.TWO);
        tau = p.multiply(q);
        xi = P.subtract(BigInteger.ONE).multiply(Q.subtract(BigInteger.ONE)).divide(tau.multiply(BigInteger.valueOf(4)));
        g = randomN().modPow(xi.multiply(BigInteger.TWO), N).negate().mod(N);
        two_tau = tau.multiply(BigInteger.TWO);
        two_tau_inv = two_tau.modInverse(N);
    }

    public BigInteger randomN()
    {
        BigInteger r;
        do{
            r = new BigInteger(k,rnd);
        }while (! (r.compareTo(N) == -1));
        return r;
    }

    public BigInteger PlainAdd(BigInteger m, BigInteger c)
    {
        return (BigInteger.ONE.add(m.multiply(N))).multiply(c).mod(N_square);
    }

    public BigInteger CipherAdd(BigInteger c_1, BigInteger c_2)
    {
        return c_1.multiply(c_2).mod(N_square);
    }

    public BigInteger PlainMul(BigInteger m, BigInteger c)
    {
        return c.modPow(m,N_square);
    }

    public BigInteger Encrypt(BigInteger m)
    {
        BigInteger r = new BigInteger(kappa, rnd);
        return (BigInteger.ONE.add(m.multiply(N))).multiply(g.modPow(r,N).modPow(N, N_square)).mod(N_square);
    }

    public BigInteger L_Func(BigInteger x)
    {
        return x.subtract(BigInteger.ONE).divide(N).mod(N);
    }

    public BigInteger Decrypt(BigInteger c)
    {
        BigInteger tmp =  L_Func(c.modPow(two_tau, N_square)).multiply(two_tau_inv).mod(N);
        return tmp.add(N_half).mod(N).subtract(N_half);
    }

    public static void main(String[] str) {
        PaillierOpt PO = new PaillierOpt(2048,448);
        long start, end;

        BigInteger m = BigInteger.valueOf(-300);
        start = System.nanoTime();
        BigInteger c = PO.Encrypt(m);
        end = System.nanoTime();
        System.out.println("PaillierOpt Encryption:"+ (end-start)/1000000.0);
        start = System.nanoTime();
        BigInteger d = PO.Decrypt(c);
        end = System.nanoTime();
        System.out.println("PaillierOpt Decryption:"+ (end-start)/1000000.0);
        System.out.println(d);

        BigInteger m_2 = BigInteger.valueOf(10);
        BigInteger c_2 = PO.PlainAdd(m_2,c);
        System.out.println(PO.Decrypt(c_2));

        BigInteger c_3 = PO.CipherAdd(c,c_2);
        System.out.println(PO.Decrypt(c_3));

        BigInteger c_4 = PO.PlainMul(m_2,c_3);
        System.out.println(PO.Decrypt(c_4));

    }
}
