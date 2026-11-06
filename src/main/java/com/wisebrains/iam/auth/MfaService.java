package com.wisebrains.iam.auth;

import org.springframework.stereotype.Service;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.security.GeneralSecurityException;
import java.io.ByteArrayOutputStream;
import java.util.Locale;
import java.util.Base64;

@Service
public class MfaService {
    private static final int TIME_STEP_SECONDS = 30;
    private static final int CODE_DIGITS = 6;

    public String generateSecret() {
        byte[] buffer = new byte[20];
        new SecureRandom().nextBytes(buffer);
        return encodeBase32(buffer);
    }

    public int generateTotp(String secret, long epochSeconds) throws GeneralSecurityException {
        byte[] key = decodeBase32(secret);
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

    public boolean validateTotp(String secret, int code) throws GeneralSecurityException {
        if (secret == null || secret.isBlank() || code < 0 || code >= (int) Math.pow(10, CODE_DIGITS)) {
            return false;
        }

        long currentEpochSeconds = System.currentTimeMillis() / 1000L;
        int windowSize = 1;

        for (int offset = -windowSize; offset <= windowSize; offset++) {
            int generated = generateTotp(secret, currentEpochSeconds + (offset * TIME_STEP_SECONDS));
            if (generated == code) {
                return true;
            }
        }

        return false;
    }

    private String encodeBase32(byte[] bytes) {
        char[] alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".toCharArray();
        StringBuilder encoded = new StringBuilder((bytes.length * 8 + 4) / 5);
        int buffer = 0;
        int bitsLeft = 0;
        for (byte value : bytes) {
            buffer = (buffer << 8) | (value & 0xFF);
            bitsLeft += 8;
            while (bitsLeft >= 5) {
                encoded.append(alphabet[(buffer >> (bitsLeft - 5)) & 0x1F]);
                bitsLeft -= 5;
            }
        }
        if (bitsLeft > 0) {
            encoded.append(alphabet[(buffer << (5 - bitsLeft)) & 0x1F]);
        }
        return encoded.toString();
    }

    private byte[] decodeBase32(String secret) {
        if (secret.endsWith("==")) {
            return Base64.getDecoder().decode(secret);
        }
        String normalized = secret.replace("=", "").replace(" ", "").toUpperCase(Locale.ROOT);
        ByteArrayOutputStream decoded = new ByteArrayOutputStream();
        int buffer = 0;
        int bitsLeft = 0;
        for (char character : normalized.toCharArray()) {
            int value;
            if (character >= 'A' && character <= 'Z') {
                value = character - 'A';
            } else if (character >= '2' && character <= '7') {
                value = character - '2' + 26;
            } else {
                throw new IllegalArgumentException("Invalid Base32 MFA secret");
            }
            buffer = (buffer << 5) | value;
            bitsLeft += 5;
            if (bitsLeft >= 8) {
                decoded.write((buffer >> (bitsLeft - 8)) & 0xFF);
                bitsLeft -= 8;
            }
        }
        if (bitsLeft > 0 && (buffer & ((1 << bitsLeft) - 1)) != 0) {
            throw new IllegalArgumentException("Invalid Base32 MFA secret padding");
        }
        return decoded.toByteArray();
    }
}
