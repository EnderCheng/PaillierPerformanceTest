package ca.uwaterloo.cheng;
import java.math.BigInteger;
import java.security.SecureRandom;

public class SymmetricHomomorphism {

    private int k0;
    private int k1;
    private int k2;
    private int k3;

    private int kappa;

    private BigInteger S_half;
    private BigInteger p;
    private BigInteger q;
    private BigInteger S;
    private BigInteger N;

    private BigInteger Max_1, Max_2;
    private BigInteger E_01, E_02;
    private int mul_depth;
    SecureRandom rnd = new SecureRandom();

//    public static int KappaSize(int k0, int k1, int security)
//    {
//        double len_1 = (security/Math.log10(security))*(k0-2*k1)*(k0-2*k1);
//        double len_2 = k0*k0;
//        double len = Math.max(len_1,len_2);
//        return (int) Math.ceil((len-k0)/k0);
//    }

    public static int CipherSize(int k0, int k1, int k2)
    {
        return (int) Math.floor((k0*k0-k1-k2)/(k0-k1-k2));
    }

//    public SymmetricHomomorphism(int k0, int k1, int kappa)
//    {
//        this.kappa = kappa;
//        this.k0 = k0;
//        this.p = BigInteger.probablePrime(k0, rnd);
//        this.q = BigInteger.ONE;
//        for(int i = 0;i<this.kappa; i++)
//        {
//            this.q = this.q.multiply(BigInteger.probablePrime(k0, rnd));
//        }
//        this.S = new BigInteger(k1, rnd);
//        this.N = this.p.multiply(this.q);
//
//        this.k0 = k0;
//        this.k1 = k1;
//        this.k3 = kappa*k0;
//        this.S_half = this.S.divide(BigInteger.TWO);
//        mul_depth = (int)Math.floor(k0/(2*k1))-1;
//        createPubKeys();
//        System.out.println("Maximum Multiplication Depth:"+ mul_depth);
//    }

    public SymmetricHomomorphism(int k0, int k1, int k2)
    {
        this.k0 = k0;
        this.k3 = k0*k0-k0;
        this.p = BigInteger.probablePrime(k0, rnd);
        this.q = BigInteger.ONE;
        for(int i = 0;i<this.k0-1; i++)
        {
            this.q = this.q.multiply(BigInteger.probablePrime(k0, rnd));
        }
        this.S = new BigInteger(k1, rnd);
        this.N = this.p.multiply(this.q);

        this.k0 = k0;
        this.k1 = k1;
        this.k2 = k2;
        Max_1 = BigInteger.TWO.pow(k2);
        Max_2 = BigInteger.TWO.pow(k3);
        this.S_half = this.S.divide(BigInteger.TWO);
        mul_depth = (int)Math.floor(k0/(this.k1+k2))-1;
        createPubKeys();
        System.out.println("Maximum Multiplication Depth:"+ mul_depth);
    }

    public BigInteger bootstrap_1(BigInteger c1, BigInteger r1)
    {
        return c1.add(r1).mod(N);
    }

    public BigInteger bootstrap_2(BigInteger c2)
    {
        BigInteger tmp = Decrypt(c2);
        return Encrypt(tmp);
    }

    public BigInteger bootstrap_3(BigInteger c3, BigInteger r1)
    {
        return c3.subtract(r1).mod(N);
    }

    public BigInteger getS() {
        return S;
    }

    public BigInteger getP() {
        return p;
    }


    public BigInteger negate(BigInteger c) {
        return c.negate().add(E_01.multiply(new BigInteger(k2,rnd)));
    }

    public BigInteger Mul(BigInteger c1, BigInteger c2)
    {
        return c1.multiply(c2).mod(N);
    }

    public BigInteger Add(BigInteger c1, BigInteger c2)
    {
        return c1.add(c2).mod(N);
    }

    public BigInteger Encrypt(BigInteger plaintext) {
        BigInteger gamma = new BigInteger(k2, rnd);
        BigInteger lambda = new BigInteger(k3, rnd);

        BigInteger tmp1 = (gamma.multiply(S)).add(plaintext);
        tmp1 = tmp1.add(lambda.multiply(p).mod(N)).mod(N);
        return tmp1;
    }

    public BigInteger PkEncrypt(BigInteger plaintext)
    {
        BigInteger r_1 = new BigInteger(k2, rnd);
        BigInteger r_2 = new BigInteger(k2, rnd);
        return plaintext.add(r_1.multiply(E_01)).add(r_2.multiply(E_02)).mod(N);
    }

    public BigInteger getN() {
        return N;
    }

    public BigInteger Decrypt(BigInteger ciphertext)
    {
        BigInteger m_pri = (ciphertext.mod(p)).mod(S);
        if(m_pri.compareTo(S_half) == -1)
        {
            return m_pri;
        }
        return m_pri.subtract(S);
    }

    public void createPubKeys(){
        E_01 = Encrypt(BigInteger.ZERO);
        E_02 = Encrypt(BigInteger.ZERO);
    }

    public int getMul_depth() {
        return mul_depth;
    }

    public static void main(String[] args)
    {
        int k0 = 330;
        int k1 = 120;
        int k2 = 80;
        SymmetricHomomorphism SHE = new SymmetricHomomorphism(k0, k1, k2);
        System.out.println("Ciphertext Size:"+k0*k0);
        System.out.println("Ciphertext Leaked Maximum:"+CipherSize(k0,k1,k2));
        long start, end;

        BigInteger m = BigInteger.valueOf(100);
        start = System.nanoTime();
        BigInteger c = SHE.Encrypt(m);
        end = System.nanoTime();
        System.out.println("SHE Encryption:"+ (end-start)/1000000.0);

        start = System.nanoTime();
        BigInteger d = SHE.Decrypt(c);
        end = System.nanoTime();
        System.out.println("SHE Decryption:"+ (end-start)/1000000.0);
        System.out.println(d);

//        start = System.nanoTime();
//        c = SHE.PkEncrypt(m);
//        end = System.nanoTime();
//        System.out.println("SHE Pubkey Encryption:"+ (end-start)/1000000.0);

        start = System.nanoTime();
        d = SHE.Decrypt(c);
        end = System.nanoTime();
        System.out.println(d);

        BigInteger m_2 = BigInteger.valueOf(5);
        BigInteger c_1 = m_2.add(c);
        System.out.println(SHE.Decrypt(c_1));

        BigInteger c_2 = m_2.multiply(c);
        System.out.println(SHE.Decrypt(c_2));

        BigInteger c_3 = c_2.add(c);
        System.out.println(SHE.Decrypt(c_3));

        BigInteger c_4 = SHE.negate(c);
        System.out.println(SHE.Decrypt(c_4));

        BigInteger large_m = new BigInteger(k1-2, new SecureRandom());
        System.out.println(large_m.compareTo(SHE.getS().divide(BigInteger.TWO)));
        BigInteger c_5 = SHE.Encrypt(large_m);
        System.out.println(large_m);
        System.out.println(SHE.Decrypt(c_5));
    }

}
