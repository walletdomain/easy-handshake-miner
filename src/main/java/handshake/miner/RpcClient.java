package handshake.miner;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Minimal JSON-RPC client for the node (hsd-style: HTTP basic auth, user "x", password = API key). */
final class RpcClient {
    static final class RpcError extends Exception {
        final int code;
        RpcError(int code, String message) { super(message); this.code = code; }
    }

    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();
    private final URI uri;
    private final String label;
    private final String auth;

    RpcClient(String url, String apiKey) {
        this.uri = URI.create(url);
        this.label = url;
        this.auth = apiKey == null || apiKey.isEmpty() ? null
                : "Basic " + Base64.getEncoder().encodeToString(("x:" + apiKey).getBytes(StandardCharsets.UTF_8));
    }

    @Override public String toString() { return label; }

    private static final Pattern ERROR = Pattern.compile("\"error\"\\s*:\\s*\\{[^}]*\"code\"\\s*:\\s*(-?\\d+)[^}]*\"message\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\"");
    private static final Pattern ERROR2 = Pattern.compile("\"error\"\\s*:\\s*\\{[^}]*\"message\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\"[^}]*\"code\"\\s*:\\s*(-?\\d+)");

    /** Calls a method and returns the raw response body (the caller picks out what it needs). */
    String call(String method, String paramsJson, Duration timeout) throws RpcError {
        String body = "{\"method\":\"" + method + "\",\"params\":" + paramsJson + ",\"id\":1}";
        HttpRequest.Builder b = HttpRequest.newBuilder(uri).timeout(timeout)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body));
        if (auth != null) b.header("Authorization", auth);
        HttpResponse<String> r;
        try {
            r = http.send(b.build(), HttpResponse.BodyHandlers.ofString());
        } catch (java.io.IOException e) {
            throw new RpcError(-1000, "cannot reach the node at " + uri + " (" + e.getClass().getSimpleName() + ": " + e.getMessage() + ")");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RpcError(-1001, "interrupted");
        }
        if (r.statusCode() == 401) throw new RpcError(401, "the node refused the API key (HTTP 401)");
        String text = r.body();
        Matcher m = ERROR.matcher(text);
        if (m.find()) throw new RpcError(Integer.parseInt(m.group(1)), m.group(2));
        m = ERROR2.matcher(text);
        if (m.find()) throw new RpcError(Integer.parseInt(m.group(2)), m.group(1));
        if (r.statusCode() != 200) throw new RpcError(r.statusCode(), "HTTP " + r.statusCode());
        return text;
    }
}
