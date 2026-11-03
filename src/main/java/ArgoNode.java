import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ArgoNode {

    private static final String PROP_NAME = "argo.properties";

    private static final String TEMPLATE = """
            # argo-node 配置（与本 jar 放在同一目录）
            # 同名环境变量存在时，优先使用环境变量
            ARGO_PORT=8080
            ARGO_TOKEN=
            ARGO_DOMAIN=
            # 留空则自动生成 UUID 并保存到 .npm/uuid
            UUID=
            WSPATH=/vless
            """;

    private static Path base;
    private static Path dir;
    private static Path sb;
    private static Path cf;
    private static Path cfg;
    private static Path uuidFile;

    private static String port;
    private static String token;
    private static String domain;
    private static String wsPath;
    private static String uuid;
    private static String arch;

    private static final HttpClient HTTP = HttpClient.newBuilder()
            .followRedirects(HttpClient.Redirect.ALWAYS)
            .build();

    private static Path jarDir() {
        try {
            URI uri = ArgoNode.class.getProtectionDomain().getCodeSource().getLocation().toURI();
            Path p = Paths.get(uri);
            return Files.isRegularFile(p) ? p.getParent() : p;
        } catch (Exception e) {
            return Paths.get(System.getProperty("user.dir"));
        }
    }

    private static Properties loadProps(Path file) throws IOException {
        Properties props = new Properties();
        if (Files.exists(file)) {
            try (var in = Files.newBufferedReader(file, StandardCharsets.UTF_8)) {
                props.load(in);
            }
        } else {
            Files.writeString(file, TEMPLATE, StandardCharsets.UTF_8);
            System.out.println("[*] 已生成配置模板: " + file);
        }
        return props;
    }

    private static String cfg(Properties props, String key, String def) {
        String env = System.getenv(key);
        if (env != null && !env.isBlank()) return env.trim();
        String v = props.getProperty(key);
        return (v == null || v.isBlank()) ? def : v.trim();
    }

    private static boolean isArm() {
        String a = System.getProperty("os.arch", "").toLowerCase();
        return a.startsWith("aarch") || a.contains("arm");
    }

    private static void init() throws IOException {
        base = jarDir();
        dir = base.resolve(".npm");
        sb = dir.resolve("sing-box");
        cf = dir.resolve("cloudflared");
        cfg = dir.resolve("config.json");
        uuidFile = dir.resolve("uuid");
        arch = isArm() ? "arm64" : "amd64";

        Files.createDirectories(dir);

        Properties props = loadProps(base.resolve(PROP_NAME));

        port = cfg(props, "ARGO_PORT", "8080");
        token = cfg(props, "ARGO_TOKEN", "");
        domain = cfg(props, "ARGO_DOMAIN", "");

        wsPath = cfg(props, "WSPATH", "/vless");
        if (!wsPath.startsWith("/")) wsPath = "/" + wsPath;

        String fixed = cfg(props, "UUID", "");
        if (!fixed.isEmpty()) {
            uuid = fixed;
        } else if (Files.exists(uuidFile) && !Files.readString(uuidFile).trim().isEmpty()) {
            uuid = Files.readString(uuidFile).trim();
        } else {
            uuid = UUID.randomUUID().toString();
            Files.writeString(uuidFile, uuid);
        }

        System.out.println("[*] 工作目录: " + dir);
        System.out.println("[*] 监听端口: " + port + "  路径: " + wsPath);
    }

    private static void download(String url, Path dest) throws Exception {
        HttpRequest req = HttpRequest.newBuilder(URI.create(url)).GET().build();
        HttpResponse<Path> res = HTTP.send(req, HttpResponse.BodyHandlers.ofFile(dest,
                StandardOpenOption.CREATE, StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING));
        if (res.statusCode() != 200) throw new IOException(res.statusCode() + " " + url);
    }

    private static void untar(Path tgz, Path target) throws Exception {
        Process p = new ProcessBuilder("tar", "-xzf", tgz.toString(), "-C", target.toString(), "--strip-components=1")
                .inheritIO().start();
        if (p.waitFor() != 0) throw new IOException("tar 解压失败");
    }

    private static void chmodX(Path p) throws IOException {
        Files.setPosixFilePermissions(p, PosixFilePermissions.fromString("rwxr-xr-x"));
    }

    private static void setup() throws Exception {
        if (!Files.exists(sb)) {
            System.out.println("[*] 拉取 sing-box");
            Path tgz = dir.resolve("sb.tgz");
            download("https://github.com/SagerNet/sing-box/releases/download/v1.11.4/sing-box-1.11.4-linux-"
                    + arch + ".tar.gz", tgz);
            untar(tgz, dir);
            Files.deleteIfExists(tgz);
        }
        if (!Files.exists(cf)) {
            System.out.println("[*] 拉取 cloudflared");
            download("https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-" + arch, cf);
        }
        chmodX(sb);
        chmodX(cf);
    }

    private static void writeConfig() throws IOException {
        String json = """
                {
                  "log": { "level": "warn", "timestamp": true },
                  "inbounds": [
                    {
                      "type": "vless",
                      "tag": "vless-ws",
                      "listen": "0.0.0.0",
                      "listen_port": %s,
                      "users": [{ "uuid": "%s" }],
                      "transport": { "type": "ws", "path": "%s" }
                    }
                  ],
                  "outbounds": [{ "type": "direct", "tag": "direct" }]
                }
                """.formatted(Integer.parseInt(port), uuid, wsPath);
        Files.writeString(cfg, json);
    }

    private static String link(String host) {
        String h = (host == null || host.isBlank())
                ? (domain.isEmpty() ? "<your-domain>" : domain)
                : host;
        return "vless://" + uuid + "@" + h + ":443?encryption=none&security=tls&sni=" + h
                + "&fp=random&type=ws&host=" + h
                + "&path=" + URLEncoder.encode(wsPath, StandardCharsets.UTF_8) + "#argo-ws";
    }

    public static void main(String[] args) throws Exception {
        init();
        setup();
        writeConfig();

        Process sbProc = new ProcessBuilder(sb.toString(), "run", "-c", cfg.toString()).inheritIO().start();
        sbProc.onExit().thenRun(() -> {
            System.out.println("sing-box exited " + sbProc.exitValue());
            System.exit(sbProc.exitValue());
        });

        List<String> cmd = new ArrayList<>(List.of(
                cf.toString(), "tunnel", "--no-autoupdate", "--url", "http://127.0.0.1:" + port));
        if (!token.isEmpty()) {
            cmd.add("run");
            cmd.add("--token");
            cmd.add(token);
        }
        Process cfProc = new ProcessBuilder(cmd).redirectErrorStream(true).start();

        AtomicBoolean done = new AtomicBoolean(false);
        Pattern pat = Pattern.compile("https://([a-z0-9-]+\\.trycloudflare\\.com)", Pattern.CASE_INSENSITIVE);

        Thread reader = new Thread(() -> {
            try (BufferedReader r = new BufferedReader(
                    new InputStreamReader(cfProc.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = r.readLine()) != null) {
                    System.out.println(line);
                    if (done.get()) continue;
                    Matcher m = pat.matcher(line);
                    if (m.find() && done.compareAndSet(false, true)) {
                        System.out.println("\n=== 节点 ===\n" + link(m.group(1)) + "\n");
                    }
                }
            } catch (IOException ignored) {
            }
        });
        reader.setDaemon(true);
        reader.start();

        cfProc.onExit().thenRun(() -> {
            System.out.println("cloudflared exited " + cfProc.exitValue());
            System.exit(cfProc.exitValue());
        });

        if (!token.isEmpty()) {
            Thread t = new Thread(() -> {
                try {
                    Thread.sleep(8000);
                } catch (InterruptedException e) {
                    return;
                }
                if (done.compareAndSet(false, true)) {
                    System.out.println(domain.isEmpty()
                            ? "\n固定隧道已启动，但未设置 ARGO_DOMAIN，请到 Cloudflare 后台绑定主机名后自行拼接链接。"
                            : "\n=== 节点 ===\n" + link(domain) + "\n");
                }
            });
            t.setDaemon(true);
            t.start();
        }

        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            cfProc.destroy();
            sbProc.destroy();
        }));
    }
}