package handshake.miner;

import java.time.Duration;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Asks a node for its mining reward address (getmineraddress) before any hashing starts. */
final class NodeCheck {
    enum Kind {
        /** The node answered with a reward address: ready to mine. */
        ADDRESS,
        /** The node answered, but no reward address is set: mining would earn nothing, so do not start. */
        NO_ADDRESS,
        /** The node has no getmineraddress (for example hsd); its reward address cannot be checked from here. */
        UNSUPPORTED,
        /** Could not reach the node, or it refused the API key. */
        UNREACHABLE
    }

    record Result(Kind kind, String text) {}

    private static final Pattern RESULT = Pattern.compile("\"result\"\\s*:\\s*\"([^\"]*)\"");

    private NodeCheck() {}

    static Result check(RpcClient node) {
        try {
            String resp = node.call("getmineraddress", "[]", Duration.ofSeconds(15));
            Matcher m = RESULT.matcher(resp);
            String addr = m.find() ? m.group(1).trim() : "";
            return addr.isEmpty() ? new Result(Kind.NO_ADDRESS, "")
                                  : new Result(Kind.ADDRESS, addr);
        } catch (RpcClient.RpcError e) {
            String msg = e.getMessage() == null ? "" : e.getMessage();
            if (e.code == -32601 || msg.toLowerCase().contains("method not found"))
                return new Result(Kind.UNSUPPORTED, "this node has no getmineraddress (hsd?)");
            return new Result(Kind.UNREACHABLE, msg);
        }
    }
}
