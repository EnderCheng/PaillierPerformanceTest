package ca.uwaterloo.cheng;

import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.RunnerException;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;

import java.math.BigInteger;
import java.util.concurrent.TimeUnit;

@BenchmarkMode(Mode.AverageTime)
@State(Scope.Benchmark)
@Fork(1)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
@Warmup(iterations = 3,time = 1, timeUnit = TimeUnit.SECONDS)
@Measurement(iterations = 3, time = 1, timeUnit = TimeUnit.SECONDS)
public class SHEBenchmark {

    int k0 = 1024;
    int k1 = 160;
    int k2 = 70;
    int level = 72;
    int kappa = SymmetricHomomorphism.KappaSize(k1,k2,level);
    SymmetricHomomorphism SHE = new SymmetricHomomorphism(k0, k1, k2, kappa);
    public BigInteger plain_input = BigInteger.valueOf(100);
    private BigInteger enc_input = BigInteger.valueOf(-100);

    private BigInteger enc_input_2 = BigInteger.valueOf(5);
    private BigInteger dec_input = SHE.Encrypt(enc_input);


    @Benchmark
    public BigInteger testPubEncryption()
    {
        return SHE.PkEncrypt(enc_input);
    }

    @Benchmark
    public BigInteger testEncryption()
    {
        return SHE.Encrypt(enc_input);
    }

    @Benchmark
    public BigInteger testDecryption()
    {
        return SHE.Decrypt(dec_input);
    }
    @Benchmark
    public BigInteger testPlainAdd()
    {
        return SHE.Add(plain_input,enc_input);
    }

    @Benchmark
    public BigInteger testCipherAdd()
    {
        return SHE.Add(plain_input,enc_input);
    }

    @Benchmark
    public BigInteger testPlainMul()
    {
        return SHE.Mul(plain_input,enc_input);
    }

    @Benchmark
    public BigInteger testCipherMul()
    {
        return SHE.Mul(enc_input,enc_input_2);
    }

    public static void main(String[] args) {

        Options opt = new OptionsBuilder()
                .include(SHEBenchmark.class.getSimpleName())
                .build();
        try {
            new Runner(opt).run();
        } catch (RunnerException e) {
            throw new RuntimeException(e);
        }
    }
}
