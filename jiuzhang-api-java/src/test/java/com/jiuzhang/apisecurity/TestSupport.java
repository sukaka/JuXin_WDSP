package com.jiuzhang.apisecurity;

import java.util.Objects;

final class TestSupport {
    private static int passed;

    private TestSupport() {
    }

    static synchronized void test(String name, ThrowingRunnable test) {
        try {
            test.run();
            passed++;
            System.out.println("PASS " + name);
        } catch (Throwable error) {
            System.err.println("FAIL " + name + ": " + error);
            throw new AssertionError(name, error);
        }
    }

    static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }

    static void equal(Object expected, Object actual, String message) {
        if (!Objects.equals(expected, actual)) {
            throw new AssertionError(message + ": expected=" + expected + ", actual=" + actual);
        }
    }

    static void rejects(Class<? extends Throwable> type, ThrowingRunnable operation) {
        try {
            operation.run();
        } catch (Throwable error) {
            if (type.isInstance(error)) return;
            throw new AssertionError("unexpected exception type: " + error, error);
        }
        throw new AssertionError("operation unexpectedly succeeded");
    }

    static int passed() {
        return passed;
    }

    @FunctionalInterface
    interface ThrowingRunnable {
        void run() throws Exception;
    }
}
