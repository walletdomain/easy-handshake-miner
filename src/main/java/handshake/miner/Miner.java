package handshake.miner;

import java.time.Duration;
import java.util.List;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.LongAdder;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The mining loop. The node does the heavy lifting (it keeps the chain, picks mempool transactions, builds and
 * validates the block); this class only needs the CURRENT work, so there is no chain data here at all.
 *
 *   fetcher thread : getwork once, then getworklp (blocks until a new block, or a changed mempool) -> newest Work
 *   worker threads : search nonces for the newest Work; a hit is sent to the node with submitwork
 *   main thread    : prints status every few seconds
 */
final class Miner {
    /** Nonces searched per (extraNonce, time) pair: about 10 s at 1.5 MH/s; then the time is refreshed. */
    private static final int SLICE = 1 << 24;

    private final List<RpcClient> nodes;
    private int active;                       // index into nodes; touched by the fetcher thread only
    private final int threads;
    private final AtomicBoolean running = new AtomicBoolean(true);
    private final LongAdder hashes = new LongAdder();
    private final LongAdder accepted = new LongAdder(), rejected = new LongAdder();
    private volatile Work current;
    private final byte[] instanceId = new byte[4];

    Miner(List<RpcClient> nodes, int threads) {
        if (nodes.isEmpty()) throw new IllegalArgumentException("at least one node is needed");
        this.nodes = List.copyOf(nodes);
        this.threads = threads;
        ThreadLocalRandom.current().nextBytes(instanceId);   // so two miners on one node never repeat each other's work
    }

    static void log(String msg) {
        System.out.println(LocalTime.now().format(DateTimeFormatter.ofPattern("HH:mm:ss")) + "  " + msg);
    }

    void stop() { running.set(false); }

    void run() throws InterruptedException {
        Thread f = new Thread(this::fetchLoop, "fetcher");
        f.setDaemon(true);
        f.start();
        for (int i = 0; i < threads; i++) {
            final int id = i;
            Thread t = new Thread(() -> workLoop(id), "miner-" + i);
            t.setDaemon(true);
            t.start();
        }
        long last = System.nanoTime(), lastHashes = 0;
        while (running.get()) {
            Thread.sleep(15_000);
            long now = System.nanoTime(), total = hashes.sum();
            double rate = (total - lastHashes) / ((now - last) / 1e9);
            last = now; lastHashes = total;
            Work w = current;
            String eta = "";
            if (w != null && rate > 0) eta = ", on average one block per " + human(w.expectedHashes() / rate);
            log(String.format("%s | height %s | blocks found %d, refused %d%s",
                    rateText(rate), w == null ? "-" : String.valueOf(w.height), accepted.sum(), rejected.sum(), eta));
        }
    }

    static String rateText(double r) {
        if (r >= 1e9) return String.format("%.2f GH/s", r / 1e9);
        if (r >= 1e6) return String.format("%.2f MH/s", r / 1e6);
        if (r >= 1e3) return String.format("%.2f kH/s", r / 1e3);
        return String.format("%.0f H/s", r);
    }

    static String human(double seconds) {
        if (seconds < 120) return String.format("%.0f s", seconds);
        if (seconds < 7200) return String.format("%.0f min", seconds / 60);
        if (seconds < 172800) return String.format("%.1f hours", seconds / 3600);
        if (seconds < 86400.0 * 730) return String.format("%.1f days", seconds / 86400);
        return String.format("%.1f years", seconds / (86400.0 * 365));
    }

    // ── getting work ─────────────────────────────────────────────────────────

    private void fetchLoop() {
        boolean first = true;
        int failures = 0;                       // consecutive failures across all nodes
        while (running.get()) {
            RpcClient node = nodes.get(active);
            try {
                String resp = first ? node.call("getwork", "[]", Duration.ofSeconds(30))
                                    : node.call("getworklp", "[]", Duration.ofMinutes(7));
                Work w = Work.parse(resp);
                w.source = node;
                Work old = current;
                current = w;
                if (old == null || old.height != w.height || old.source != node)
                    log("New work from " + node + ": height " + w.height + ", about "
                            + String.format("%.3g", w.expectedHashes()) + " hashes per block on average");
                first = false;
                failures = 0;
            } catch (RpcClient.RpcError e) {
                if (e.getMessage() != null && e.getMessage().contains("timed out") && !first) { continue; }   // long poll simply expired
                current = null;                // do not mine on work that may be stale
                first = true;
                failures++;
                if (nodes.size() > 1) {
                    active = (active + 1) % nodes.size();
                    log("Node " + node + " says: " + e.getMessage() + ". Switching to " + nodes.get(active) + ".");
                    if (failures % nodes.size() == 0) {          // every node failed in a row: wait before the next round
                        int wait = Math.min(30, 1 << Math.min(5, failures / nodes.size()));
                        log("No node could give work. Retrying in " + wait + " s.");
                        sleep(wait * 1000L);
                    }
                } else {
                    int wait = Math.min(30, 1 << Math.min(5, failures - 1));
                    log("Node says: " + e.getMessage() + " (retrying in " + wait + " s)");
                    sleep(wait * 1000L);
                }
            } catch (RuntimeException e) {
                log("Unusable answer from " + node + ": " + e.getMessage());
                current = null;
                first = true;
                if (nodes.size() > 1) active = (active + 1) % nodes.size();
                sleep(5000);
            }
        }
    }

    private static void sleep(long ms) {
        try { Thread.sleep(ms); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
    }

    // ── searching ────────────────────────────────────────────────────────────

    private void workLoop(int id) {
        Pow pow = new Pow();
        byte[] extra = new byte[24];
        System.arraycopy(instanceId, 0, extra, 0, 4);
        extra[4] = (byte) id; extra[5] = (byte) (id >> 8);
        long counter = ThreadLocalRandom.current().nextLong() & 0x00FFFFFFFFFFFFL;   // random start, then counts up
        while (running.get()) {
            Work w = current;
            if (w == null) { sleep(200); continue; }
            counter++;
            for (int i = 0; i < 8; i++) extra[8 + i] = (byte) (counter >>> (8 * i));
            long time = w.timeNow();
            pow.setup(w.data, time, extra, w.target);
            int n = 0;
            long batch = 0;
            for (; n < SLICE; n++) {
                if (pow.meets(n)) {
                    hashes.add(batch); batch = 0;
                    submit(w, n, time, extra);
                    if (current == w) current = null;     // the chain moves on; wait for the node's next work
                    break;
                }
                if ((++batch & 0x3FFF) == 0) {
                    hashes.add(batch); batch = 0;
                    if (current != w || !running.get()) break;
                }
            }
            hashes.add(batch);
        }
    }

    private static final Pattern OK = Pattern.compile("\"result\"\\s*:\\s*\\[\\s*true");
    private static final Pattern REASON = Pattern.compile("\"result\"\\s*:\\s*\\[\\s*false\\s*,\\s*\"([^\"]*)\"");

    private void submit(Work w, int nonce, long time, byte[] extra) {
        byte[] d = w.data.clone();
        for (int i = 0; i < 4; i++) d[i] = (byte) (nonce >>> (8 * i));
        for (int i = 0; i < 8; i++) d[4 + i] = (byte) (time >>> (8 * i));
        System.arraycopy(extra, 0, d, 128, 24);
        log("Found a solution for height " + w.height + " (nonce " + Integer.toUnsignedString(nonce) + "). Sending it to " + w.source + "...");
        try {
            String resp = w.source.call("submitwork", "[\"" + Hex.encode(d) + "\",\"" + "00".repeat(32) + "\"]", Duration.ofSeconds(60));
            if (OK.matcher(resp).find()) {
                accepted.increment();
                log("*** BLOCK ACCEPTED at height " + w.height + " *** by " + w.source + ". The reward goes to the reward address set on that node.");
            } else {
                rejected.increment();
                Matcher m = REASON.matcher(resp);
                log("The node refused it: " + (m.find() ? m.group(1) : resp));
            }
        } catch (RpcClient.RpcError e) {
            rejected.increment();
            log("Could not submit: " + e.getMessage());
        }
    }
}
