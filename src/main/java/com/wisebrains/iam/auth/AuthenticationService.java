package com.wisebrains.iam.auth;

import com.wisebrains.iam.UserRepository;
import com.wisebrains.iam.model.User;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;
import java.security.GeneralSecurityException;

@Service
public class AuthenticationService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final TokenService tokenService;
    private final MfaService mfaService;

    public AuthenticationService(UserRepository userRepository,
                                 PasswordEncoder passwordEncoder,
                                 TokenService tokenService,
                                 MfaService mfaService) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.tokenService = tokenService;
        this.mfaService = mfaService;
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
        if (!passwordEncoder.matches(password, user.getPassword())) {
            return Optional.empty();
        }

        if (user.isMfaEnabled()) {
            try {
                if (mfaCode == null || !mfaService.validateTotp(user.getMfaSecret(), Integer.parseInt(mfaCode))) {
                    return Optional.empty();
                }
            } catch (GeneralSecurityException | IllegalArgumentException e) {
                return Optional.empty();
            }
        }

        return Optional.of(user);
    }

    public String issueToken(User user) {
        return tokenService.generateJwt(user);
    }
}

