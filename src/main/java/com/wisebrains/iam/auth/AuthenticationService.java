package com.wisebrains.iam.auth;

import com.wisebrains.iam.account.AccountLifecycleService;
import com.wisebrains.iam.model.User;
import com.wisebrains.iam.user.UserRepository;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class AuthenticationService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final TokenService tokenService;
    private final AccountLifecycleService accountLifecycleService;

    public AuthenticationService(UserRepository userRepository,
                                 PasswordEncoder passwordEncoder,
                                 TokenService tokenService,
                                 AccountLifecycleService accountLifecycleService) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.tokenService = tokenService;
        this.accountLifecycleService = accountLifecycleService;
    }

    public Optional<User> authenticate(String username, String password, String mfaCode) {
        Optional<User> optionalUser = userRepository.findByUsername(username);
        if (optionalUser.isEmpty()) {
            return Optional.empty();
        }

        User user = optionalUser.get();
        if (!user.isEnabled()) {
            return Optional.empty();
        }
        if (!user.isEmailVerified()) {
            return Optional.empty();
        }
        if (!passwordEncoder.matches(password, user.getPassword())) {
            return Optional.empty();
        }

        if (user.isMfaEnabled()) {
            if (!accountLifecycleService.verifyMfaForAuthentication(user, mfaCode)) {
                return Optional.empty();
            }
        }

        return Optional.of(user);
    }

    public String issueToken(User user) {
        return tokenService.generateJwt(user);
    }
}
