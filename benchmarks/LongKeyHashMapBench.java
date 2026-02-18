import java.util.HashMap;
import java.util.Map;

/**
 * Java built-in HashMap benchmark using packed long keys (simulating 6-byte MAC packed in low 48 bits).
 *
 * Usage:
 *   javac benchmarks/LongKeyHashMapBench.java
 *   java -cp benchmarks LongKeyHashMapBench --ops 100000000 --keys 200000 --mode get [--pack-each-get]
 */
public class LongKeyHashMapBench {
    private static final long PUT_MUL = 6364136223846793005L;
    private static final long PUT_ADD = 1442695040888963407L;
    private static final long GET_MUL = 2862933555777941757L;
    private static final long GET_ADD = 3037000493L;

    private enum Mode {
        BOTH,
        PUT,
        GET
    }

    private static final class Config {
        long ops = 5_000_000L;
        int keys = 20_000;
        Mode mode = Mode.BOTH;
        boolean packEachGet = false;
    }

    public static void main(String[] args) {
        Config cfg;
        try {
            cfg = parseArgs(args);
        } catch (IllegalArgumentException ex) {
            System.err.println(ex.getMessage());
            printUsageAndExit(2);
            return;
        }

        byte[][] macKeys = generateMacKeys(cfg.keys);
        long[] keys = packMacKeys(macKeys);
        Long[] boxedKeys = boxKeys(keys);

        System.out.println("Java HashMap<Long,Long> benchmark (packed 6-byte keys)");
        System.out.printf(
            "keys: %d, ops: %d, mode: %s, pack_each_get: %s%n",
            cfg.keys,
            cfg.ops,
            cfg.mode.name().toLowerCase(),
            cfg.packEachGet
        );

        if (cfg.mode == Mode.PUT || cfg.mode == Mode.BOTH) {
            Result putRes = runPut(boxedKeys, cfg.ops);
            System.out.printf("put: total = %.3f ms, ns/op = %.2f%n", putRes.totalMs, putRes.nsPerOp);
        }
        if (cfg.mode == Mode.GET || cfg.mode == Mode.BOTH) {
            Result getRes = runGet(boxedKeys, macKeys, cfg.ops, cfg.packEachGet);
            System.out.printf("get: total = %.3f ms, ns/op = %.2f%n", getRes.totalMs, getRes.nsPerOp);
        }
    }

    private static Config parseArgs(String[] args) {
        Config cfg = new Config();
        for (int i = 0; i < args.length; i++) {
            String a = args[i];
            switch (a) {
                case "--ops" -> {
                    if (i + 1 >= args.length) {
                        throw new IllegalArgumentException("--ops requires a value");
                    }
                    cfg.ops = parsePositiveLong(args[++i], "--ops");
                }
                case "--keys" -> {
                    if (i + 1 >= args.length) {
                        throw new IllegalArgumentException("--keys requires a value");
                    }
                    long parsed = parsePositiveLong(args[++i], "--keys");
                    if (parsed > Integer.MAX_VALUE) {
                        throw new IllegalArgumentException("--keys too large");
                    }
                    cfg.keys = (int) parsed;
                }
                case "--mode" -> {
                    if (i + 1 >= args.length) {
                        throw new IllegalArgumentException("--mode requires a value");
                    }
                    String mode = args[++i];
                    cfg.mode = switch (mode) {
                        case "both" -> Mode.BOTH;
                        case "put" -> Mode.PUT;
                        case "get" -> Mode.GET;
                        default -> throw new IllegalArgumentException("invalid --mode: " + mode);
                    };
                }
                case "--pack-each-get" -> cfg.packEachGet = true;
                case "--help", "-h" -> {
                    printUsageAndExit(0);
                    return cfg;
                }
                default -> throw new IllegalArgumentException("unknown argument: " + a);
            }
        }
        return cfg;
    }

    private static long parsePositiveLong(String s, String name) {
        long v;
        try {
            v = Long.parseLong(s);
        } catch (NumberFormatException ex) {
            throw new IllegalArgumentException("invalid value for " + name + ": " + s);
        }
        if (v <= 0) {
            throw new IllegalArgumentException(name + " must be > 0");
        }
        return v;
    }

    private static byte[][] generateMacKeys(int count) {
        byte[][] out = new byte[count][6];
        for (int i = 0; i < count; i++) {
            long x = i & 0x0000_ffff_ffffL;
            out[i][0] = (byte) (x & 0xff);
            out[i][1] = (byte) ((x >>> 8) & 0xff);
            out[i][2] = (byte) ((x >>> 16) & 0xff);
            out[i][3] = (byte) ((x >>> 24) & 0xff);
            out[i][4] = (byte) ((x >>> 32) & 0xff);
            out[i][5] = (byte) ((x >>> 40) & 0xff);
        }
        return out;
    }

    private static long[] packMacKeys(byte[][] macKeys) {
        long[] out = new long[macKeys.length];
        for (int i = 0; i < macKeys.length; i++) {
            out[i] = packMacToLong(macKeys[i]);
        }
        return out;
    }

    private static long packMacToLong(byte[] mac) {
        return ((long) mac[0] & 0xffL)
            | (((long) mac[1] & 0xffL) << 8)
            | (((long) mac[2] & 0xffL) << 16)
            | (((long) mac[3] & 0xffL) << 24)
            | (((long) mac[4] & 0xffL) << 32)
            | (((long) mac[5] & 0xffL) << 40);
    }

    private static Long[] boxKeys(long[] keys) {
        Long[] out = new Long[keys.length];
        for (int i = 0; i < keys.length; i++) {
            out[i] = keys[i];
        }
        return out;
    }

    private static Result runPut(Long[] keys, long ops) {
        Map<Long, Long> map = new HashMap<>(keys.length * 2);
        long rng = 0x0123_4567_89ab_cdefL;
        long start = System.nanoTime();
        for (long i = 0; i < ops; i++) {
            rng = rng * PUT_MUL + PUT_ADD;
            int idx = (int) Long.remainderUnsigned(rng, keys.length);
            map.put(keys[idx], i);
        }
        long elapsed = System.nanoTime() - start;
        if (map.size() == -1) {
            System.out.println("unreachable");
        }
        return Result.fromNanos(elapsed, ops);
    }

    private static Result runGet(Long[] keys, byte[][] macKeys, long ops, boolean packEachGet) {
        Map<Long, Long> map = new HashMap<>(keys.length * 2);
        for (int i = 0; i < keys.length; i++) {
            map.put(keys[i], (long) i);
        }

        long rng = 0xfedc_ba98_7654_3210L;
        long checksum = 0;
        long start = System.nanoTime();
        for (long i = 0; i < ops; i++) {
            rng = rng * GET_MUL + GET_ADD;
            int idx = (int) Long.remainderUnsigned(rng, keys.length);
            Long key = packEachGet ? packMacToLong(macKeys[idx]) : keys[idx];
            Long v = map.get(key); // 100% known-key hit expectation
            if (v == null) {
                throw new IllegalStateException("internal benchmark error: get miss in 100% hit mode");
            }
            checksum ^= v;
        }
        long elapsed = System.nanoTime() - start;
        if (checksum == Long.MIN_VALUE) {
            System.out.println("unreachable");
        }
        return Result.fromNanos(elapsed, ops);
    }

    private static final class Result {
        final double totalMs;
        final double nsPerOp;

        Result(double totalMs, double nsPerOp) {
            this.totalMs = totalMs;
            this.nsPerOp = nsPerOp;
        }

        static Result fromNanos(long nanos, long ops) {
            return new Result(nanos / 1_000_000.0, nanos / (double) ops);
        }
    }

    private static void printUsageAndExit(int code) {
        System.err.println("Usage: java LongKeyHashMapBench [--ops N] [--keys K] [--mode both|put|get] [--pack-each-get]");
        System.err.println("Defaults: --ops 5000000 --keys 20000 --mode both (without per-get packing)");
        System.exit(code);
    }
}
