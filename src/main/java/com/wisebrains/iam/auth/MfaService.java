package com.wisebrains.iam.auth;

import org.springframework.stereotype.Service;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

@Service
public class MfaService {
    private static final int TIME_STEP_SECONDS = 30;
    private static final int CODE_DIGITS = 6;

    public String generateSecret() {
        byte[] buffer = new byte[20];
        new SecureRandom().nextBytes(buffer);
        return Base64.getEncoder().encodeToString(buffer);
    }

    public int generateTotp(String secret, long epochSeconds) throws Exception {
        byte[] key = Base64.getDecoder().decode(secret);
        long counter = epochSeconds / TIME_STEP_SECONDS;

        byte[] data = new byte[8];
        for (int i = 7; i >= 0; i--) {
            data[i] = (byte) (counter & 0xFF);
            counter >>= 8;
        }

        SecretKeySpec signKey = new SecretKeySpec(key, "HmacSHA1");
        Mac mac = Mac.getInstance("HmacSHA1");
        mac.init(signKey);
        byte[] hash = mac.doFinal(data);

        int offset = hash[hash.length - 1] & 0xF;
        int binary = ((hash[offset] & 0x7F) << 24)
                | ((hash[offset + 1] & 0xFF) << 16)
                | ((hash[offset + 2] & 0xFF) << 8)
                | (hash[offset + 3] & 0xFF);

        int otp = binary % (int) Math.pow(10, CODE_DIGITS);
        return otp;
    }

    public boolean validateTotp(String secret, int code) throws Exception {
        long currentEpochSeconds = System.currentTimeMillis() / 1000L;
        int windowSize = 2;

        for (int offset = -windowSize; offset <= windowSize; offset++) {
            int generated = generateTotp(secret, currentEpochSeconds + (offset * TIME_STEP_SECONDS));
            if (generated == code) {
                return true;
            }
        }

        return false;
    }
}
