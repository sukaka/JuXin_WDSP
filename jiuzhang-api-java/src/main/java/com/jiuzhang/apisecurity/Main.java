package com.jiuzhang.apisecurity;

import java.nio.file.Path;

public final class Main {
    private Main() {
    }

    public static void main(String[] arguments) {
        try {
            var options = Options.parse(arguments);
            var salt = System.getenv("JIUZHANG_IDENTITY_SALT");
            var config = GatewayConfig.load(options.config(), salt);
            var schemas = SchemaRegistry.load(config.schemaLocation());
            var authorization = AuthorizationPolicy.load(
                config.schemaLocation().resolveSibling("authz.example.json"),
                config.identitySalt()
            );
            if (options.checkOnly()) {
                System.out.println("configuration and security models are valid");
                return;
            }
            var gateway = new ApiGateway(
                config, schemas, authorization, System.getenv("JIUZHANG_JWT_HMAC_SECRET")
            );
            var admin = new AdminServer(
                config, gateway.events(), schemas, authorization, gateway.behavior()
            );
            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                admin.stop();
                gateway.stop();
            }));
            gateway.start();
            admin.start();
            System.out.println("API security gateway listening on " + gateway.address());
            System.out.println("read-only administration listening on " + config.adminListen());
        } catch (Exception error) {
            System.err.println("startup failed: " + error.getMessage());
            System.exit(1);
        }
    }

    private record Options(Path config, boolean checkOnly) {
        private static Options parse(String[] arguments) {
            if (arguments.length == 1) return new Options(Path.of(arguments[0]), false);
            if (arguments.length == 2 && arguments[0].equals("--check-config")) {
                return new Options(Path.of(arguments[1]), true);
            }
            throw new IllegalArgumentException(
                "usage: jiuzhang-api-security [--check-config] <config.properties>"
            );
        }
    }
}
