package ca.uwaterloo.cheng;

import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.RunnerException;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;
import org.openjdk.jmh.runner.options.TimeValue;

import java.math.BigInteger;
import java.util.concurrent.TimeUnit;

@BenchmarkMode(Mode.AverageTime)
@State(Scope.Benchmark)
@Fork(1)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
@Warmup(iterations = 3,time = 1, timeUnit = TimeUnit.SECONDS)
@Measurement(iterations = 3, time = 1, timeUnit = TimeUnit.SECONDS)
public class PaillierBenchmark {

    PaillierOpt PO = new PaillierOpt(2048,448);
    public BigInteger plain_input = BigInteger.valueOf(100);
    private BigInteger enc_input = BigInteger.valueOf(-100);

    private BigInteger enc_input_2 = BigInteger.valueOf(5);
    private BigInteger dec_input = PO.Encrypt(enc_input);

    @Benchmark
    public BigInteger testEncryption()
    {
        return PO.Encrypt(enc_input);
    }

    @Benchmark
    public BigInteger testDecryption()
    {
        return PO.Decrypt(dec_input);
    }
    @Benchmark
    public BigInteger testPlainAdd()
    {
        return PO.PlainAdd(plain_input,enc_input);
    }

    @Benchmark
    public BigInteger testCipherAdd()
    {
        return PO.CipherAdd(enc_input,enc_input_2);
    }

    @Benchmark
    public BigInteger testPlainMul()
    {
        return PO.PlainMul(plain_input,enc_input);
    }

    public static void main(String[] args) {

        Options opt = new OptionsBuilder()
                .include(PaillierBenchmark.class.getSimpleName())
                .build();
        try {
            new Runner(opt).run();
        } catch (RunnerException e) {
            throw new RuntimeException(e);
        }
    }
}
