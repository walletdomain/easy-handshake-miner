package handshake.miner;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** One unit of work from the node's getwork: a 256-byte header to search nonces for, and the target to beat. */
final class Work {
    final byte[] data;      // 256-byte miner-format header
    final byte[] target;    // 32 bytes, big-endian: a hash at or below this wins
    final int height;
    final long nodeTime;    // node's clock when it issued the work
    final long fee;
    final long fetchedNanos = System.nanoTime();
    final long id;
    /** The node that issued this work; a solution must go back to the same node. */
    volatile RpcClient source;

    private static final java.util.concurrent.atomic.AtomicLong IDS = new java.util.concurrent.atomic.AtomicLong();

    private Work(byte[] data, byte[] target, int height, long nodeTime, long fee) {
        this.data = data; this.target = target; this.height = height; this.nodeTime = nodeTime; this.fee = fee;
        this.id = IDS.incrementAndGet();
    }

    private static String str(String json, String key) {
        Matcher m = Pattern.compile("\"" + key + "\"\\s*:\\s*\"([^\"]*)\"").matcher(json);
        return m.find() ? m.group(1) : null;
    }

    private static long num(String json, String key) {
        Matcher m = Pattern.compile("\"" + key + "\"\\s*:\\s*(-?\\d+)").matcher(json);
        return m.find() ? Long.parseLong(m.group(1)) : 0;
    }

    static Work parse(String json) {
        String d = str(json, "data"), t = str(json, "target");
        if (d == null || t == null) throw new IllegalArgumentException("the node's answer has no work in it: " + json);
        byte[] data = Hex.decode(d), target = Hex.decode(t);
        if (data.length != 256) throw new IllegalArgumentException("work data is " + data.length + " bytes, expected 256");
        if (target.length != 32) throw new IllegalArgumentException("target is " + target.length + " bytes, expected 32");
        return new Work(data, target, (int) num(json, "height"), num(json, "time"), num(json, "fee"));
    }

    /** The clock to put in the header: the node's time when it issued the work plus how long we have held it. */
    long timeNow() {
        return nodeTime + (System.nanoTime() - fetchedNanos) / 1_000_000_000L;
    }

    /** Expected number of hashes to find one block at this target: 2^256 / (target + 1). */
    double expectedHashes() {
        java.math.BigInteger t = new java.math.BigInteger(1, target).add(java.math.BigInteger.ONE);
        return new java.math.BigDecimal(java.math.BigInteger.ONE.shiftLeft(256))
                .divide(new java.math.BigDecimal(t), java.math.MathContext.DECIMAL64).doubleValue();
    }
}
