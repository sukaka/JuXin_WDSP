package com.jiuzhang.apisecurity;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.HexFormat;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public final class Fingerprints {
    private Fingerprints() {
    }

    public static String hmac(String salt, String value) {
        try {
            var mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(salt.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            var digest = mac.doFinal(value.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(java.util.Arrays.copyOf(digest, 16));
        } catch (GeneralSecurityException error) {
            throw new IllegalStateException("HMAC-SHA256 is unavailable", error);
        }
    }

    public static boolean constantTimeEquals(byte[] left, byte[] right) {
        return java.security.MessageDigest.isEqual(left, right);
    }
}
