import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
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

    private static final String SING_BOX_URL =
            "https://github.com/SagerNet/sing-box/releases/download/v1.11.4/sing-box-1.11.4-linux-%s.tar.gz";
    private static final String CLOUDFLARED_URL =
            "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-%s";

    private static final String TEMPLATE =
            "# argo-node 配置（与本 jar 放在同一目录）\n"
          + "# 同名环境变量存在时，优先使用环境变量\n"
          + "ARGO_PORT=8080\n"
          + "ARGO_TOKEN=\n"
          + "ARGO_DOMAIN=\n"
          + "# 留空则自动生成 UUID 并保存到 .npm/uuid\n"
          + "UUID=\n"
          + "WSPATH=/vless\n"
          + "# GitHub 加速前缀，留空直连。例: https://ghfast.top/\n"
          + "GH_PROXY=\n"
          + "# 预置二进制目录，优先于下载\n"
          + "PRELOAD_DIR=/opt/preload\n";

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
    private static String ghProxy;
    private static String preloadDir;

    private static Boolean hasCurl;
    private static Boolean hasWget;

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

        ghProxy = cfg(props, "GH_PROXY", "");
        if (!ghProxy.isEmpty() && !ghProxy.endsWith("/")) ghProxy = ghProxy + "/";

        preloadDir = cfg(props, "PRELOAD_DIR", "/opt/preload");

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
        System.out.println("[*] 架构: " + arch);

        try {
            System.out.println("[*] DNS: github.com -> " + InetAddress.getByName("github.com").getHostAddress());
        } catch (Exception e) {
            System.out.println("[!] DNS 解析 github.com 失败: " + e);
        }
    }

    private static int run(List<String> cmd) {
        try {
            return new ProcessBuilder(cmd)
                    .redirectOutput(ProcessBuilder.Redirect.DISCARD)
                    .redirectError(ProcessBuilder.Redirect.INHERIT)
                    .start().waitFor();
        } catch (Exception e) {
            return -1;
        }
    }

    private static boolean which(String c) {
        return run(List.of("sh", "-c", "command -v " + c)) == 0;
    }

    private static boolean fetch(String url, Path dest) throws Exception {
        if (hasCurl == null) hasCurl = which("curl");
        if (hasWget == null) hasWget = which("wget");

        if (hasCurl && run(List.of("curl", "-fsSL", "--retry", "2",
                "--connect-timeout", "15", "-o", dest.toString(), url)) == 0
                && Files.size(dest) > 0) {
            return true;
        }
        if (hasWget && run(List.of("wget", "-q", "-O", dest.toString(), url)) == 0
                && Files.size(dest) > 0) {
            return true;
        }

        HttpRequest req = HttpRequest.newBuilder(URI.create(url)).GET().build();
        HttpResponse<Path> res = HTTP.send(req, HttpResponse.BodyHandlers.ofFile(dest,
                StandardOpenOption.CREATE, StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING));
        return res.statusCode() == 200;
    }

    private static void download(String url, Path dest) throws Exception {
        Exception last = null;
        for (int attempt = 1; attempt <= 4; attempt++) {
            List<String> urls = new ArrayList<>();
            if (!ghProxy.isEmpty()) urls.add(ghProxy + url);
            urls.add(url);
            for (String u : urls) {
                try {
                    Files.deleteIfExists(dest);
                    if (fetch(u, dest) && Files.size(dest) > 100_000) return;
                    System.out.println("[!] 文件异常: " + u);
                } catch (Exception e) {
                    last = e;
                    System.out.println("[!] 下载失败 " + u + " -> " + e);
                }
            }
            Thread.sleep(1500L * attempt);
        }
        Files.deleteIfExists(dest);
        throw new IOException("下载失败: " + url, last);
    }

    private static void untar(Path tgz, Path target) throws Exception {
        Process p = new ProcessBuilder("tar", "-xzf", tgz.toString(), "-C", target.toString(),
                "--strip-components=1").inheritIO().start();
        if (p.waitFor() != 0) throw new IOException("tar 解压失败");
    }

    private static void chmodX(Path p) throws IOException {
        Files.setPosixFilePermissions(p, PosixFilePermissions.fromString("rwxr-xr-x"));
    }

    private static void ensureSingBox() throws Exception {
        if (Files.exists(sb) && Files.size(sb) > 100_000) return;
        Files.deleteIfExists(sb);

        Path pre = Paths.get(preloadDir).resolve("sing-box");
        if (Files.exists(pre) && Files.size(pre) > 100_000) {
            System.out.println("[*] 使用预置二进制 sing-box");
            Files.copy(pre, sb, StandardCopyOption.REPLACE_EXISTING);
            return;
        }
        System.out.println("[*] 拉取 sing-box");
        Path tgz = dir.resolve("sb.tgz");
        download(SING_BOX_URL.formatted(arch), tgz);
        untar(tgz, dir);
        Files.deleteIfExists(tgz);
    }

    private static void ensureCloudflared() throws Exception {
        if (Files.exists(cf) && Files.size(cf) > 100_000) return;
        Files.deleteIfExists(cf);

        Path pre = Paths.get(preloadDir).resolve("cloudflared");
        if (Files.exists(pre) && Files.size(pre) > 100_000) {
            System.out.println("[*] 使用预置二进制 cloudflared");
            Files.copy(pre, cf, StandardCopyOption.REPLACE_EXISTING);
            return;
        }
        System.out.println("[*] 拉取 cloudflared");
        download(CLOUDFLARED_URL.formatted(arch), cf);
    }

    private static void setup() throws Exception {
        ensureSingBox();
        ensureCloudflared();
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

    private static void runNode() throws Exception {
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

    public static void main(String[] args) {
        try {
            runNode();
        } catch (Exception e) {
            System.err.println("[x] 启动失败: " + e);
            e.printStackTrace();
            System.exit(1);
        }
    }
}
