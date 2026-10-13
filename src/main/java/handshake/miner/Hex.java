package handshake.miner;

final class Hex {
    private Hex() {}
    private static final char[] D = "0123456789abcdef".toCharArray();

    static String encode(byte[] b) {
        char[] c = new char[b.length * 2];
        for (int i = 0; i < b.length; i++) { c[2 * i] = D[(b[i] >> 4) & 15]; c[2 * i + 1] = D[b[i] & 15]; }
        return new String(c);
    }

    static byte[] decode(String s) {
        if (s.length() % 2 != 0) throw new IllegalArgumentException("odd hex length");
        byte[] b = new byte[s.length() / 2];
        for (int i = 0; i < b.length; i++) {
            int hi = Character.digit(s.charAt(2 * i), 16), lo = Character.digit(s.charAt(2 * i + 1), 16);
            if (hi < 0 || lo < 0) throw new IllegalArgumentException("bad hex");
            b[i] = (byte) (hi * 16 + lo);
        }
        return b;
    }
}
