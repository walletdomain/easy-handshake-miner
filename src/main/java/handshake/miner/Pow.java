package handshake.miner;

/**
 * Handshake's proof-of-work hash, specialised for mining.
 *
 * For one block header the hash is
 *
 *   prehead  = nonce(4) time(8) padding(20) prevBlock(32) treeRoot(32) commitHash(32)      (128 bytes)
 *   left     = BLAKE2b-512(prehead)
 *   right    = SHA3-256(prehead || padding(8))
 *   hash     = BLAKE2b-256(left || padding(32) || right)        (then XOR the block's mask; the mask is 0 here)
 *
 * where padding(n)[i] = prevBlock[i] XOR treeRoot[i], and
 *   commitHash = BLAKE2b-256( BLAKE2b-256(extraNonce reservedRoot witnessRoot merkleRoot version bits) || maskHash ).
 *
 * Only the nonce and the time change while searching, so everything else is computed once per (extraNonce, time)
 * and one attempt costs exactly two BLAKE2b compressions and two Keccak-f[1600] permutations (the SHA3 input is
 * exactly one full 136-byte block, so its padding needs a second permutation). Nothing is allocated per attempt.
 *
 * One instance per thread; instances are not thread-safe.
 */
final class Pow {
    // ── BLAKE2b ──────────────────────────────────────────────────────────────
    private static final long[] IV = {
            0x6a09e667f3bcc908L, 0xbb67ae8584caa73bL, 0x3c6ef372fe94f82bL, 0xa54ff53a5f1d36f1L,
            0x510e527fade682d1L, 0x9b05688c2b3e6c1fL, 0x1f83d9abfb41bd6bL, 0x5be0cd19137e2179L };

    private static final int[][] SIGMA = {
            {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
            {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
            {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
            {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
            {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
            {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
            {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
            {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
            {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
            {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0}};

    private final long[] v = new long[16];

    /** One BLAKE2b compression of a single, final block of {@code len} bytes; h is updated in place. */
    private void compress(long[] h, long[] m, long len) {
        System.arraycopy(h, 0, v, 0, 8);
        System.arraycopy(IV, 0, v, 8, 8);
        v[12] ^= len;
        v[14] = ~v[14];
        for (int r = 0; r < 12; r++) {
            int[] s = SIGMA[r % 10];
            g(0, 4, 8, 12, m[s[0]], m[s[1]]);
            g(1, 5, 9, 13, m[s[2]], m[s[3]]);
            g(2, 6, 10, 14, m[s[4]], m[s[5]]);
            g(3, 7, 11, 15, m[s[6]], m[s[7]]);
            g(0, 5, 10, 15, m[s[8]], m[s[9]]);
            g(1, 6, 11, 12, m[s[10]], m[s[11]]);
            g(2, 7, 8, 13, m[s[12]], m[s[13]]);
            g(3, 4, 9, 14, m[s[14]], m[s[15]]);
        }
        for (int i = 0; i < 8; i++) h[i] ^= v[i] ^ v[i + 8];
    }

    private void g(int a, int b, int c, int d, long x, long y) {
        long[] v = this.v;
        v[a] += v[b] + x; v[d] = Long.rotateRight(v[d] ^ v[a], 32);
        v[c] += v[d];     v[b] = Long.rotateRight(v[b] ^ v[c], 24);
        v[a] += v[b] + y; v[d] = Long.rotateRight(v[d] ^ v[a], 16);
        v[c] += v[d];     v[b] = Long.rotateRight(v[b] ^ v[c], 63);
    }

    /** BLAKE2b with a 32-byte output of up to 128 input bytes (setup only, not in the hot loop). */
    byte[] blake256(byte[] in, int len) {
        long[] m = new long[16];
        for (int i = 0; i < len; i++) m[i >> 3] |= (in[i] & 0xFFL) << (8 * (i & 7));
        long[] h = IV.clone();
        h[0] ^= 0x01010020L;
        compress(h, m, len);
        byte[] out = new byte[32];
        for (int i = 0; i < 32; i++) out[i] = (byte) (h[i >> 3] >>> (8 * (i & 7)));
        return out;
    }

    // ── Keccak-f[1600] / SHA3-256 ────────────────────────────────────────────
    private static final long[] RC = {
            0x0000000000000001L, 0x0000000000008082L, 0x800000000000808aL, 0x8000000080008000L,
            0x000000000000808bL, 0x0000000080000001L, 0x8000000080008081L, 0x8000000000008009L,
            0x000000000000008aL, 0x0000000000000088L, 0x0000000080008009L, 0x000000008000000aL,
            0x000000008000808bL, 0x800000000000008bL, 0x8000000000008089L, 0x8000000000008003L,
            0x8000000000008002L, 0x8000000000000080L, 0x000000000000800aL, 0x800000008000000aL,
            0x8000000080008081L, 0x8000000000008080L, 0x0000000080000001L, 0x8000000080008008L};
    private static final int[] ROT = new int[25];   // rotation of lane x+5y
    private static final int[] PI = new int[25];    // destination of lane x+5y
    static {
        int[][] r = {{0, 36, 3, 41, 18}, {1, 44, 10, 45, 2}, {62, 6, 43, 15, 61}, {28, 55, 25, 21, 56}, {27, 20, 39, 8, 14}};
        for (int x = 0; x < 5; x++) for (int y = 0; y < 5; y++) {
            ROT[x + 5 * y] = r[x][y];
            PI[x + 5 * y] = y + 5 * ((2 * x + 3 * y) % 5);
        }
    }

    private final long[] st = new long[25];
    private final long[] kb = new long[25];
    private final long[] kc = new long[5];

    private void keccakF() {
        long[] a = st, b = kb, c = kc;
        for (int round = 0; round < 24; round++) {
            for (int x = 0; x < 5; x++) c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
            for (int x = 0; x < 5; x++) {
                long d = c[(x + 4) % 5] ^ Long.rotateLeft(c[(x + 1) % 5], 1);
                for (int y = 0; y < 25; y += 5) a[x + y] ^= d;
            }
            for (int i = 0; i < 25; i++) b[PI[i]] = Long.rotateLeft(a[i], ROT[i]);
            for (int y = 0; y < 25; y += 5)
                for (int x = 0; x < 5; x++) a[x + y] = b[x + y] ^ (~b[(x + 1) % 5 + y] & b[(x + 2) % 5 + y]);
            a[0] ^= RC[round];
        }
    }

    // ── per-work state ───────────────────────────────────────────────────────
    private final long[] pre = new long[16];     // prehead as little-endian words; word 0 carries nonce + time-low
    private long padLane;                         // padding(8) as one lane
    private final long[] pad32 = new long[4];     // padding(32) as lanes
    private final long[] target = new long[4];    // target as big-endian words
    private final long[] h1 = new long[8], h2 = new long[8], m2 = new long[16];
    private long word0Base;

    /** Fixes everything but the nonce: {@code work} is the 256-byte miner-format header. */
    void setup(byte[] work, long time, byte[] extraNonce24, byte[] targetBytes32) {
        byte[] prev = java.util.Arrays.copyOfRange(work, 32, 64);
        byte[] tree = java.util.Arrays.copyOfRange(work, 64, 96);
        byte[] pad = new byte[32];
        for (int i = 0; i < 32; i++) pad[i] = (byte) (prev[i] ^ tree[i]);

        byte[] sub = new byte[128];
        System.arraycopy(extraNonce24, 0, sub, 0, 24);
        System.arraycopy(work, 152, sub, 24, 32);      // reservedRoot
        System.arraycopy(work, 184, sub, 56, 32);      // witnessRoot
        System.arraycopy(work, 216, sub, 88, 32);      // merkleRoot
        System.arraycopy(work, 248, sub, 120, 4);      // version
        System.arraycopy(work, 252, sub, 124, 4);      // bits
        byte[] subHash = blake256(sub, 128);
        byte[] cm = new byte[64];
        System.arraycopy(subHash, 0, cm, 0, 32);
        System.arraycopy(work, 96, cm, 32, 32);        // maskHash
        byte[] commit = blake256(cm, 64);

        byte[] ph = new byte[128];                     // nonce stays 0 here
        for (int i = 0; i < 8; i++) ph[4 + i] = (byte) (time >>> (8 * i));
        System.arraycopy(pad, 0, ph, 12, 20);
        System.arraycopy(prev, 0, ph, 32, 32);
        System.arraycopy(tree, 0, ph, 64, 32);
        System.arraycopy(commit, 0, ph, 96, 32);
        for (int i = 0; i < 16; i++) pre[i] = le64(ph, i * 8);
        word0Base = pre[0] & 0xFFFFFFFF00000000L;

        padLane = le64(pad, 0);
        for (int i = 0; i < 4; i++) { pad32[i] = le64(pad, i * 8); }
        for (int i = 0; i < 4; i++) target[i] = be64(targetBytes32, i * 8);
    }

    private static long le64(byte[] b, int o) {
        long x = 0;
        for (int i = 7; i >= 0; i--) x = (x << 8) | (b[o + i] & 0xFFL);
        return x;
    }

    private static long be64(byte[] b, int o) {
        long x = 0;
        for (int i = 0; i < 8; i++) x = (x << 8) | (b[o + i] & 0xFFL);
        return x;
    }

    /** Computes the hash for one nonce; the four words are the hash's bytes read little-endian (h2[0..3]). */
    private void compute(int nonce) {
        pre[0] = word0Base | (nonce & 0xFFFFFFFFL);

        System.arraycopy(IV, 0, h1, 0, 8);
        h1[0] ^= 0x01010040L;                          // BLAKE2b-512, no key
        compress(h1, pre, 128);

        long[] s = st;
        System.arraycopy(pre, 0, s, 0, 16);
        s[16] = padLane;
        java.util.Arrays.fill(s, 17, 25, 0L);
        keccakF();
        s[0] ^= 0x06L;                                 // SHA3 padding lives in a block of its own
        s[16] ^= 0x8000000000000000L;
        keccakF();

        System.arraycopy(h1, 0, m2, 0, 8);
        System.arraycopy(pad32, 0, m2, 8, 4);
        m2[12] = s[0]; m2[13] = s[1]; m2[14] = s[2]; m2[15] = s[3];
        System.arraycopy(IV, 0, h2, 0, 8);
        h2[0] ^= 0x01010020L;                          // BLAKE2b-256
        compress(h2, m2, 128);
    }

    /** True if the hash for this nonce is at or below the target. */
    boolean meets(int nonce) {
        compute(nonce);
        for (int i = 0; i < 4; i++) {
            int c = Long.compareUnsigned(Long.reverseBytes(h2[i]), target[i]);
            if (c != 0) return c < 0;
        }
        return true;
    }

    /** The full 32-byte hash for a nonce (tests and logging). */
    byte[] hash(int nonce) {
        compute(nonce);
        byte[] out = new byte[32];
        for (int i = 0; i < 32; i++) out[i] = (byte) (h2[i >> 3] >>> (8 * (i & 7)));
        return out;
    }
}
