package handshake.miner;

import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

/**
 * The miner's home folder, ~/.easy-handshake-miner, and its config file {@code miner.conf}.
 *
 * miner.conf holds one node per line, in the form  IPADDRESS:PORT:API-KEY  (the API key may be left empty:
 * 127.0.0.1:12037: ). With several lines the first working node is used and the rest are fallbacks. Blank lines and
 * lines starting with # are ignored. An IPv6 address goes in brackets: [::1]:12037:KEY. A host name works too.
 *
 * The first time the miner starts without a config file, it asks for one node and writes the file.
 */
final class MinerConfig {
    static final String DIR_NAME = ".easy-handshake-miner";
    static final String FILE_NAME = "miner.conf";
    static final int DEFAULT_PORT = 12037;

    private MinerConfig() {}

    static Path dir() { return Path.of(System.getProperty("user.home"), DIR_NAME); }
    static Path file() { return dir().resolve(FILE_NAME); }

    /** One configured node. */
    record Node(String host, int port, String key) {
        String url() { return "http://" + (host.contains(":") ? "[" + host + "]" : host) + ":" + port; }
        String line() { return (host.contains(":") ? "[" + host + "]" : host) + ":" + port + ":" + key; }
    }

    /** Parses one IPADDRESS:PORT:API-KEY line. Throws IllegalArgumentException with a plain-language reason. */
    static Node parseLine(String line) {
        String s = line.trim();
        String host, rest;
        if (s.startsWith("[")) {                                   // [ipv6]:port:key
            int close = s.indexOf(']');
            if (close < 0 || close + 1 >= s.length() || s.charAt(close + 1) != ':')
                throw new IllegalArgumentException("expected [IPv6]:PORT:API-KEY");
            host = s.substring(1, close);
            rest = s.substring(close + 2);
        } else {
            int c = s.indexOf(':');
            if (c < 0) throw new IllegalArgumentException("expected IPADDRESS:PORT:API-KEY");
            host = s.substring(0, c);
            rest = s.substring(c + 1);
        }
        int c2 = rest.indexOf(':');
        if (c2 < 0) throw new IllegalArgumentException("expected IPADDRESS:PORT:API-KEY (the second colon is missing; leave the key empty if the node has none)");
        String portText = rest.substring(0, c2).trim();
        String key = rest.substring(c2 + 1).trim();
        if (host.isBlank()) throw new IllegalArgumentException("the node address is empty");
        int port;
        try { port = Integer.parseInt(portText); }
        catch (NumberFormatException e) { throw new IllegalArgumentException("the port '" + portText + "' is not a number"); }
        if (port < 1 || port > 65535) throw new IllegalArgumentException("the port " + port + " is outside 1-65535");
        return new Node(host.trim(), port, key);
    }

    /** Reads the node list from the config file. */
    static List<Node> load(Path file) throws IOException {
        List<Node> nodes = new ArrayList<>();
        List<String> lines = Files.readAllLines(file, StandardCharsets.UTF_8);
        for (int i = 0; i < lines.size(); i++) {
            String l = lines.get(i).trim();
            if (l.isEmpty() || l.startsWith("#")) continue;
            try { nodes.add(parseLine(l)); }
            catch (IllegalArgumentException e) {
                throw new IOException(file + ", line " + (i + 1) + ": " + e.getMessage());
            }
        }
        if (nodes.isEmpty())
            throw new IOException(file + " has no node in it. Add a line like  127.0.0.1:" + DEFAULT_PORT + ":YOUR-API-KEY  or delete the file to be asked again.");
        return nodes;
    }

    /** Loads the config, running the first-time questions if there is no file yet. */
    static List<Node> loadOrCreate(InputStream in, PrintStream out) throws IOException {
        Path f = file();
        if (Files.exists(f)) return load(f);

        out.println();
        out.println("Welcome to the Easy Handshake Miner. This is the first start, so a few questions.");
        out.println("The miner does not keep a blockchain; it asks a Handshake node for work and sends found blocks back.");
        out.println("The block reward is paid to the reward address set on that node (not here).");
        out.println();
        Scanner sc = new Scanner(in, StandardCharsets.UTF_8);
        List<Node> nodes = new ArrayList<>();
        nodes.add(askNode(sc, out));

        Files.createDirectories(dir());
        StringBuilder sb = new StringBuilder();
        sb.append("# Easy Handshake Miner: the node to mine for, as  IPADDRESS:PORT:API-KEY  (leave the key empty if the node has none).\n");
        sb.append("# To add a fallback node (or several), add them at the end of this file, one per line, in the same format as the\n");
        sb.append("# primary node below. The first working node is used; the others are only used if it fails.\n");
        sb.append("# Lines starting with # are ignored. IPv6 addresses go in brackets: [::1]:12037:KEY\n");
        for (Node n : nodes) sb.append(n.line()).append('\n');
        Files.writeString(f, sb.toString(), StandardCharsets.UTF_8);
        try { Files.setPosixFilePermissions(f, PosixFilePermissions.fromString("rw-------")); }   // it holds API keys
        catch (UnsupportedOperationException | IOException ignored) { /* Windows */ }
        out.println();
        out.println("Saved " + f);
        out.println("To add a fallback node, edit that file and add a second line with the fallback node's address in the");
        out.println("same format (IPADDRESS:PORT:API-KEY). Delete the file to be asked these questions again.");
        out.println();
        return nodes;
    }

    private static Node askNode(Scanner sc, PrintStream out) throws IOException {
        while (true) {
            out.print("Enter the IP address of the node the miner should talk to [127.0.0.1]: ");
            out.flush();
            String host = readLine(sc);
            if (host.startsWith("[") && host.endsWith("]")) host = host.substring(1, host.length() - 1);
            if (host.isEmpty()) host = "127.0.0.1";
            out.print("Enter the RPC port of the node: [" + DEFAULT_PORT + "]: ");
            out.flush();
            String port = readLine(sc);
            if (port.isEmpty()) port = String.valueOf(DEFAULT_PORT);
            out.print("Enter the API-KEY of the node (empty if it has none): ");
            out.flush();
            String key = readLine(sc);
            Node n;
            try { n = parseLine((host.contains(":") ? "[" + host + "]" : host) + ":" + port + ":" + key); }
            catch (IllegalArgumentException e) { out.println("  That does not work: " + e.getMessage() + ". Let's try that node again."); continue; }

            out.println("  Asking the node for its mining reward address ...");
            NodeCheck.Result r = NodeCheck.check(new RpcClient(n.url(), n.key().isEmpty() ? null : n.key()));
            switch (r.kind()) {
                case ADDRESS -> { out.println("  Reward address on this node: " + r.text()); return n; }
                case UNSUPPORTED -> { out.println("  Connected. This node cannot report its reward address (" + r.text() + "); make sure one is set on it."); return n; }
                case NO_ADDRESS -> {
                    out.println("  Connected, but this node has no mining reward address yet. Set one on the node (admin page, or the");
                    out.println("  setmineraddress RPC) before mining; the miner will not start until it is set. The node is saved anyway.");
                    return n;
                }
                case UNREACHABLE -> {
                    out.println("  Could not use that node: " + r.text());
                    out.print("  Save it anyway? [y/N]: ");
                    out.flush();
                    if (readLine(sc).toLowerCase().startsWith("y")) return n;
                    out.println("  Let's try that node again.");
                }
            }
        }
    }

    private static String readLine(Scanner sc) throws IOException {
        if (!sc.hasNextLine())
            throw new IOException("No answer available (the miner is not running in a terminal). Create " + file()
                    + " yourself with a line like  127.0.0.1:" + DEFAULT_PORT + ":YOUR-API-KEY");
        return sc.nextLine().trim();
    }
}
