package com.jiuzhang.apisecurity;

public final class TestMain {
    private TestMain() {
    }

    public static void main(String[] arguments) {
        JsonTests.run();
        CoreTests.run();
        SchemaTests.run();
        SecurityTests.run();
        GatewayIntegrationTest.run();
        System.out.println("All tests passed: " + TestSupport.passed());
    }
}
