package com.wisebrains.iam;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
public class AccountEmailService {
    private final JavaMailSender mailSender;
    private final String fromAddress;
    private final String publicBaseUrl;

    public AccountEmailService(JavaMailSender mailSender,
                               @Value("${iam.email.from}") String fromAddress,
                               @Value("${iam.public-base-url}") String publicBaseUrl) {
        this.mailSender = mailSender;
        this.fromAddress = fromAddress;
        this.publicBaseUrl = publicBaseUrl.replaceAll("/+$", "");
    }

    public void sendVerification(String email, String rawToken) {
        send(email, "Verify your email address",
                "Verify your email address using this link. It expires in 24 hours:\n\n"
                        + publicBaseUrl + "/api/auth/email/verify?token=" + rawToken);
    }

    public void sendPasswordReset(String email, String rawToken) {
        send(email, "Reset your password",
                "Use this link to reset your password. It expires in 30 minutes:\n\n"
                        + publicBaseUrl + "/reset-password?token=" + rawToken);
    }

    private void send(String recipient, String subject, String body) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom(fromAddress);
        message.setTo(recipient);
        message.setSubject(subject);
        message.setText(body);
        mailSender.send(message);
    }
}
