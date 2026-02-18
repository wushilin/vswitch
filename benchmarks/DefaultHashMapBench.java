import java.util.HashMap;
import java.util.Map;

/**
 * Standalone Java benchmark for built-in HashMap with 6-byte keys.
 *
 * Usage:
 *   javac benchmarks/DefaultHashMapBench.java
 *   java -cp benchmarks DefaultHashMapBench --ops 100000000 --keys 200000 --mode get
 *
 * Options:
 *   --ops  N            Number of operations (default: 5000000)
 *   --keys K            Unique key count (default: 20000)
 *   --mode both|put|get Benchmark mode (default: both)
 */
public class DefaultHashMapBench {
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
    }

    private static final class MacKey {
        private final byte[] b; // exactly 6 bytes
        private final int hash;

        MacKey(byte[] b6) {
            this.b = b6;
            int h = 1;
            for (int i = 0; i < 6; i++) {
                h = 31 * h + (b6[i] & 0xff);
            }
            this.hash = h;
        }

        @Override
        public int hashCode() {
            return hash;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (!(o instanceof MacKey other)) {
                return false;
            }
            for (int i = 0; i < 6; i++) {
                if (this.b[i] != other.b[i]) {
                    return false;
                }
            }
            return true;
        }
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

        MacKey[] keys = generateKeys(cfg.keys);
        System.out.println("Java Default HashMap benchmark (6-byte keys)");
        System.out.printf("keys: %d, ops: %d, mode: %s%n", cfg.keys, cfg.ops, cfg.mode.name().toLowerCase());

        if (cfg.mode == Mode.PUT || cfg.mode == Mode.BOTH) {
            Result putRes = runPut(keys, cfg.ops);
            System.out.printf("put: total = %.3f ms, ns/op = %.2f%n", putRes.totalMs, putRes.nsPerOp);
        }
        if (cfg.mode == Mode.GET || cfg.mode == Mode.BOTH) {
            Result getRes = runGet(keys, cfg.ops);
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

    private static MacKey[] generateKeys(int count) {
        MacKey[] out = new MacKey[count];
        for (int i = 0; i < count; i++) {
            long x = i & 0xffff_ffffL;
            byte[] b = new byte[6];
            b[0] = (byte) (x & 0xff);
            b[1] = (byte) ((x >>> 8) & 0xff);
            b[2] = (byte) ((x >>> 16) & 0xff);
            b[3] = (byte) ((x >>> 24) & 0xff);
            b[4] = 0;
            b[5] = 0;
            out[i] = new MacKey(b);
        }
        return out;
    }

    private static Result runPut(MacKey[] keys, long ops) {
        Map<MacKey, Long> map = new HashMap<>(keys.length * 2);
        long rng = 0x0123_4567_89ab_cdefL;
        long start = System.nanoTime();
        for (long i = 0; i < ops; i++) {
            rng = rng * PUT_MUL + PUT_ADD;
            int idx = (int) Long.remainderUnsigned(rng, keys.length);
            map.put(keys[idx], i);
        }
        long elapsed = System.nanoTime() - start;
        // Prevent optimization.
        if (map.size() == -1) {
            System.out.println("unreachable");
        }
        return Result.fromNanos(elapsed, ops);
    }

    private static Result runGet(MacKey[] keys, long ops) {
        Map<MacKey, Long> map = new HashMap<>(keys.length * 2);
        for (int i = 0; i < keys.length; i++) {
            map.put(keys[i], (long) i);
        }

        long rng = 0xfedc_ba98_7654_3210L;
        long checksum = 0;
        long start = System.nanoTime();
        for (long i = 0; i < ops; i++) {
            rng = rng * GET_MUL + GET_ADD;
            int idx = (int) Long.remainderUnsigned(rng, keys.length);
            Long v = map.get(keys[idx]); // 100% known-key hit expectation
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
        System.err.println("Usage: java DefaultHashMapBench [--ops N] [--keys K] [--mode both|put|get]");
        System.err.println("Defaults: --ops 5000000 --keys 20000 --mode both");
        System.exit(code);
    }
}
