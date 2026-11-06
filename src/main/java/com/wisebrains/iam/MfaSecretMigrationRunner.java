package com.wisebrains.iam;

import com.wisebrains.iam.model.User;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashSet;
import java.util.Set;

@Component
public class MfaSecretMigrationRunner implements CommandLineRunner {
    private final UserRepository userRepository;
    private final MfaSecretCipher mfaSecretCipher;

    public MfaSecretMigrationRunner(UserRepository userRepository, MfaSecretCipher mfaSecretCipher) {
        this.userRepository = userRepository;
        this.mfaSecretCipher = mfaSecretCipher;
    }

    @Override
    @Transactional
    public void run(String... args) {
        Set<Long> userIds = new HashSet<>();
        userRepository.findAllByMfaSecretIsNotNull().forEach(user -> userIds.add(user.getId()));
        userRepository.findAllByPendingMfaSecretIsNotNull().forEach(user -> userIds.add(user.getId()));
        for (User user : userRepository.findAllById(userIds)) {
            String secret = user.getMfaSecret();
            if (secret != null && !secret.startsWith("enc:v1:")) {
                user.setMfaSecret(mfaSecretCipher.encrypt(secret));
            }
            String pendingSecret = user.getPendingMfaSecret();
            if (pendingSecret != null && !pendingSecret.startsWith("enc:v1:")) {
                user.setPendingMfaSecret(mfaSecretCipher.encrypt(pendingSecret));
            }
        }
    }
}
