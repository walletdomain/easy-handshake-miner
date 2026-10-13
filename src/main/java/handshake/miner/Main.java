package handshake.miner;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Easy Handshake Miner.
 *
 *   java -jar handshake-miner.jar                      (first start asks for the node and saves ~/.easy-handshake-miner/miner.conf)
 *   java -jar handshake-miner.jar --threads 4
 *   java -jar handshake-miner.jar --url http://127.0.0.1:12037 --key YOUR_API_KEY   (overrides the config file)
 *   java -jar handshake-miner.jar --selftest
 *   java -jar handshake-miner.jar --benchmark 10
 *
 * The nodes live in ~/.easy-handshake-miner/miner.conf, one per line as IPADDRESS:PORT:API-KEY (see MinerConfig).
 */
public final class Main {
    private Main() {}

    public static void main(String[] args) throws Exception {
        String url = null, key = null;      // --url / --key override the config file (handy for tests)
        int threads = Math.max(1, Runtime.getRuntime().availableProcessors());
        boolean selftest = false;
        int bench = 0;

        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--url" -> url = args[++i];
                case "--key" -> key = args[++i];
                case "--threads" -> threads = Math.max(1, Integer.parseInt(args[++i]));
                case "--selftest" -> selftest = true;
                case "--benchmark" -> bench = i + 1 < args.length && !args[i + 1].startsWith("--") ? Integer.parseInt(args[++i]) : 10;
                case "--help", "-h" -> { usage(); return; }
                default -> { System.err.println("Unknown option: " + args[i]); usage(); System.exit(2); }
            }
        }

        if (selftest) System.exit(selfTest() ? 0 : 1);
        if (bench > 0) { benchmark(threads, bench); return; }

        if (!selfTest()) {
            System.err.println("The hash self-test failed, so this miner would produce invalid work. Not starting.");
            System.exit(1);
        }
        java.util.List<RpcClient> nodes = new java.util.ArrayList<>();
        java.util.List<String> names = new java.util.ArrayList<>();
        if (url != null) {                  // command-line override
            String[] urls = url.split("\\s*,\\s*");
            String[] keys = key == null ? new String[0] : key.split(",", -1);
            for (int i = 0; i < urls.length; i++) {
                nodes.add(new RpcClient(urls[i], keys.length == 0 ? null : keys[Math.min(i, keys.length - 1)].trim()));
                names.add(urls[i]);
            }
        } else {
            try {
                for (MinerConfig.Node n : MinerConfig.loadOrCreate(System.in, System.out)) {
                    nodes.add(new RpcClient(n.url(), n.key().isEmpty() ? null : n.key()));
                    names.add(n.url());
                }
            } catch (java.io.IOException e) {
                System.err.println(e.getMessage());
                System.exit(2);
            }
        }
        Miner.log("Mining with " + threads + " thread(s) for " + (nodes.size() == 1 ? "the node at " + names.get(0)
                : nodes.size() + " nodes (" + String.join(", ", names) + "); the first working node is used, the others are fallbacks"));
        nodes = awaitUsableNodes(nodes);
        Miner m = new Miner(nodes, threads);
        Runtime.getRuntime().addShutdownHook(new Thread(m::stop));
        m.run();
    }

    /**
     * Asks every node for its reward address (getmineraddress) first. Mining starts only once at least one node
     * has one (or is an hsd-style node that cannot say). Nodes without an address are left out; if every answering
     * node lacks one the miner stops with instructions. Unreachable nodes are retried until one answers.
     */
    private static java.util.List<RpcClient> awaitUsableNodes(java.util.List<RpcClient> all) throws InterruptedException {
        int round = 0;
        while (true) {
            java.util.List<RpcClient> usable = new java.util.ArrayList<>();
            int noAddress = 0, unreachable = 0;
            for (RpcClient n : all) {
                NodeCheck.Result r = NodeCheck.check(n);
                switch (r.kind()) {
                    case ADDRESS -> { usable.add(n); if (round == 0) Miner.log(n + ": block rewards are paid to " + r.text()); }
                    case UNSUPPORTED -> { usable.add(n); if (round == 0) Miner.log(n + ": reward address cannot be checked on this node (" + r.text() + ")"); }
                    case NO_ADDRESS -> { noAddress++; Miner.log(n + ": no mining reward address is set on this node. Set one on its admin page or with the setmineraddress RPC."); }
                    case UNREACHABLE -> { unreachable++; Miner.log(n + ": " + r.text()); }
                }
            }
            if (!usable.isEmpty()) return usable;
            if (unreachable == 0) {
                System.err.println("No node has a mining reward address, so mining would earn nothing. Set one, then start the miner again.");
                System.exit(3);
            }
            Miner.log("Waiting for a node to become available; trying again in 15 s.");
            Thread.sleep(15_000);
            round++;
        }
    }

    private static void usage() {
        System.out.println("""
                Easy Handshake Miner
                  --url URL[,URL2,..] use these node(s) instead of the config file (first working one wins)
                  --key KEY[,KEY2,..] API key(s) for --url (one key is used for every node)
                  --threads N      worker threads (default: all cores)
                  --selftest       check the hash against known blocks and exit
                  --benchmark [S]  measure hash speed for S seconds (default 10) and exit
                Nodes are read from ~/.easy-handshake-miner/miner.conf (IPADDRESS:PORT:API-KEY per line);
                the first start asks for them. The block reward goes to the mining reward address configured on the NODE (its admin page or the
                setmineraddress RPC; on hsd: --coinbase-address). Works with this project node and with hsd.""");
    }

    /** Known blocks (regtest chain and the real mainnet genesis): our hash must equal the chain's. */
    static boolean selfTest() throws Exception {
        int ok = 0, bad = 0;
        try (InputStream in = Main.class.getResourceAsStream("/vectors.txt")) {
            if (in == null) { System.err.println("vectors.txt is missing from the jar"); return false; }
            BufferedReader r = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8));
            Pow pow = new Pow();
            byte[] allOnes = new byte[32];
            java.util.Arrays.fill(allOnes, (byte) 0xff);
            for (String line; (line = r.readLine()) != null; ) {
                if (line.isBlank() || line.startsWith("#")) continue;
                String[] p = line.split("\t");
                byte[] work = Hex.decode(p[0]), expect = Hex.decode(p[1]);
                int nonce = (work[0] & 0xFF) | (work[1] & 0xFF) << 8 | (work[2] & 0xFF) << 16 | (work[3] & 0xFF) << 24;
                long time = 0;
                for (int i = 7; i >= 0; i--) time = (time << 8) | (work[4 + i] & 0xFFL);
                byte[] extra = java.util.Arrays.copyOfRange(work, 128, 152);
                pow.setup(work, time, extra, expect);          // target = the hash itself: must just meet it
                boolean same = java.util.Arrays.equals(pow.hash(nonce), expect) && pow.meets(nonce);
                if (same) {
                    byte[] below = expect.clone();             // one less than the hash must not meet the target
                    for (int i = 31; i >= 0; i--) { if (below[i]-- != 0) break; }
                    pow.setup(work, time, extra, below);
                    same = !pow.meets(nonce);
                }
                if (same) ok++; else bad++;
            }
        }
        System.out.println("Self-test: " + ok + " known blocks hash correctly, " + bad + " wrong.");
        return bad == 0 && ok > 0;
    }

    private static void benchmark(int threads, int seconds) throws Exception {
        System.out.println("Benchmark: " + threads + " thread(s), " + seconds + " s ...");
        java.util.concurrent.atomic.LongAdder total = new java.util.concurrent.atomic.LongAdder();
        long end = System.nanoTime() + seconds * 1_000_000_000L;
        Thread[] ts = new Thread[threads];
        for (int t = 0; t < threads; t++) {
            final int id = t;
            ts[t] = new Thread(() -> {
                Pow pow = new Pow();
                byte[] work = new byte[256];
                java.util.Arrays.fill(work, (byte) (id + 1));
                pow.setup(work, 1_700_000_000L, new byte[24], new byte[32]);   // target 0: never hit
                int n = 0;
                long cnt = 0;
                while (System.nanoTime() < end) {
                    for (int i = 0; i < 20000; i++) pow.meets(n++);
                    cnt += 20000;
                }
                total.add(cnt);
            });
            ts[t].start();
        }
        for (Thread t : ts) t.join();
        System.out.println(Miner.rateText(total.sum() / (double) seconds) + " in total.");
    }
}
