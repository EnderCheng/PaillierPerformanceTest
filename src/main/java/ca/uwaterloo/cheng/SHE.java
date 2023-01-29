package ca.uwaterloo.cheng;
import java.math.BigInteger;
import java.security.SecureRandom;

public class SHE {

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
    private BigInteger E_01, E_02;
    private int mul_depth;
    SecureRandom rnd = new SecureRandom();

    public SHE(int k0, int k1, int k2, int kappa)
    {
        this.kappa = kappa;
        this.k0 = k0;
        this.p = BigInteger.probablePrime(k0, rnd);
        this.q = BigInteger.ONE;
        for(int i = 0;i<this.kappa; i++)
        {
            this.q = this.q.multiply(BigInteger.probablePrime(k0, rnd));
        }
        this.S = new BigInteger(k1, rnd);
        this.N = this.p.multiply(this.q);

        this.k0 = k0;
        this.k1 = k1;
        this.k2 = k2;
        this.k3 = kappa*k0;
        this.S_half = this.S.divide(BigInteger.TWO);
        mul_depth = (int)Math.floor(k0/(2*k1))-1;
        createPubKeys();
        System.out.println("maximum multiplication times:"+ mul_depth);
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

    public BigInteger getValue()
    {
        return new BigInteger(k2-2,rnd);
    }

    public BigInteger getS() {
        return S;
    }

    public BigInteger getP() {
        return p;
    }

    public BigInteger mul(BigInteger c1, BigInteger c2)
    {
        return c1.multiply(c2).mod(N);
    }

    public BigInteger add(BigInteger c1, BigInteger c2)
    {
        return c1.add(c2).mod(N);
    }

    public BigInteger Encrypt(BigInteger plaintext) {
        BigInteger gamma = new BigInteger(k1, rnd);
        BigInteger lambda = new BigInteger(k3, rnd);

        BigInteger tmp1 = (gamma.multiply(S)).add(plaintext);
        BigInteger tmp2 = (lambda.multiply(p)).add(BigInteger.ONE);
        return (tmp1.multiply(tmp2)).mod(N);
    }

    public BigInteger pubEncrypt(BigInteger plaintext)
    {
        BigInteger r_1 = new BigInteger(k1, rnd);
        BigInteger r_2 = new BigInteger(k1, rnd);
        return plaintext.add(r_1.multiply(E_01)).add(r_2.multiply(E_02)).mod(N);
    }

    public Matrix<BigInteger> Encrypt(Matrix<BigInteger> matrix)
    {
        int row = matrix.getRows();
        int col = matrix.getCols();
        Matrix<BigInteger> enc_mat = new Matrix<>(row,col);
        for(int i=0;i<row;i++)
        {
            for(int j=0;j<col;j++){
                BigInteger tmp = matrix.get(i,j);
                enc_mat.set(i,j,pubEncrypt(tmp));
            }
        }
        return enc_mat;
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
        long start, end;
        SHE she = new SHE(1024, 160, 80, 1);
        BigInteger a = BigInteger.valueOf(100000);
        BigInteger b = BigInteger.valueOf(200000);
        start = System.nanoTime();
        BigInteger c = she.Encrypt(a);
        c = c.add(BigInteger.valueOf(50000));
        end = System.nanoTime();
        System.out.println("encryption:"+ (end-start));

//        start = System.nanoTime();
//        BigInteger plaintext = she.Decrypt(c);
//        end = System.nanoTime();
//        System.out.println("decryption:"+ (end-start));
//        System.out.println(plaintext);
//        BigInteger r = she.getValue();
//        BigInteger b1 = she.bootstrap_1(c,r);
//        BigInteger b2 = she.bootstrap_2(b1);
//        c = she.bootstrap_3(b2,r);
        start = System.nanoTime();
        c = c.multiply(BigInteger.valueOf(20000));
        end = System.nanoTime();
        System.out.println("plaintext * ciphertext:"+ (end-start));
//        BigInteger b = she.Encrypt(BigInteger.valueOf(2));
//        start = System.nanoTime();
//        c = she.mul(c,b);
//        end = System.nanoTime();
//        System.out.println("ciphertext * ciphertext:"+ (end-start));

        start = System.nanoTime();
        BigInteger plaintext = she.Decrypt(c);
        end = System.nanoTime();
        System.out.println("decryption:"+ (end-start));
        System.out.println(plaintext);

        start = System.nanoTime();
        BigInteger c_pub = she.pubEncrypt(a);
        end = System.nanoTime();
        System.out.println("pubkey encryption:"+ (end-start));

        start = System.nanoTime();
        c_pub = c_pub.multiply(BigInteger.valueOf(1000));
        end = System.nanoTime();
        System.out.println("plaintext * ciphertext:"+ (end-start));

//        start = System.nanoTime();
//        c_pub = she.mul(c_pub,b);
//        end = System.nanoTime();
//        System.out.println("ciphertext * ciphertext:"+ (end-start));

        start = System.nanoTime();
        BigInteger plaintext_pub = she.Decrypt(c_pub);
        end = System.nanoTime();
        System.out.println("pubkey decryption:"+ (end-start));
        System.out.println(plaintext_pub);

    }

}
