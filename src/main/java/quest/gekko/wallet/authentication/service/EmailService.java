package quest.gekko.wallet.authentication.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.JavaMailSenderImpl;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;
import quest.gekko.wallet.common.config.properties.ApplicationProperties;
import quest.gekko.wallet.authentication.exception.AuthenticationException;

import jakarta.mail.MessagingException;
import jakarta.mail.Transport;
import jakarta.mail.internet.MimeMessage;
import jakarta.mail.Session;
import quest.gekko.wallet.security.util.SecurityUtil;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Properties;

@Service
@RequiredArgsConstructor
@Slf4j
public class EmailService {
    private final JavaMailSender mailSender;
    private final ApplicationProperties appProperties;

    @Value("${spring.mail.username}")
    private String fromEmail;

    public void sendVerificationCode(final String toEmail, final String code) {
        log.info("=== EMAIL DEBUGGING START ===");
        log.info("Attempting to send verification code to: {}", SecurityUtil.maskEmail(toEmail));

        debugMailConfiguration();

        try {
            final MimeMessage message = mailSender.createMimeMessage();
            final MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

            helper.setFrom(fromEmail, appProperties.getName());
            helper.setTo(toEmail);
            helper.setSubject("🔐 Your Security Code - " + appProperties.getName());

            final String htmlContent = buildVerificationEmailHtml(code);
            helper.setText(htmlContent, true);

            debugMessage(message);

            log.info("Calling mailSender.send()...");
            mailSender.send(message);
            log.info("mailSender.send() completed without exception");

            verifyEmailSent(message);

            log.info("Verification code email sent successfully to: {}", SecurityUtil.maskEmail(toEmail));
        } catch (MessagingException e) {
            log.error("Failed to send verification code email to: {}", SecurityUtil.maskEmail(toEmail), e);
            throw new AuthenticationException("Failed to send verification email", e);
        } catch (Exception e) {
            log.error("Unexpected error sending verification code to: {}", SecurityUtil.maskEmail(toEmail), e);
            throw new AuthenticationException("Email service unavailable", e);
        }

        log.info("=== EMAIL DEBUGGING END ===");
    }

    public void sendWelcomeEmail(final String toEmail, final String clientIp) {
        try {
            final MimeMessage message = mailSender.createMimeMessage();
            final MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

            helper.setFrom(fromEmail, appProperties.getName());
            helper.setTo(toEmail);
            helper.setSubject("🎉 Welcome to " + appProperties.getName() + "!");

            final String htmlContent = buildWelcomeEmailHtml(clientIp);
            helper.setText(htmlContent, true);

            mailSender.send(message);

            log.info("Welcome email sent to: {}", SecurityUtil.maskEmail(toEmail));
        } catch (Exception e) {
            log.error("Failed to send welcome email to: {}", SecurityUtil.maskEmail(toEmail), e);
        }
    }

    private void debugMailConfiguration() {
        log.info("=== MAIL CONFIGURATION DEBUG ===");

        if (mailSender instanceof JavaMailSenderImpl javaMailSender) {
            log.info("Host: {}", javaMailSender.getHost());
            log.info("Port: {}", javaMailSender.getPort());
            log.info("Username: {}", javaMailSender.getUsername());
            log.info("Password: {}", javaMailSender.getPassword() != null ? "SET" : "NOT_SET");
            log.info("Default encoding: {}", javaMailSender.getDefaultEncoding());
            log.info("Protocol: {}", javaMailSender.getProtocol());

            final Properties props = javaMailSender.getJavaMailProperties();
            log.info("JavaMail Properties:");
            props.forEach((key, value) -> log.info("  {}: {}", key, value));

            try {
                log.info("Testing SMTP connection...");
                javaMailSender.testConnection();
                log.info("SMTP connection test: SUCCESS");
            } catch (Exception e) {
                log.error("SMTP connection test: FAILED", e);
            }
        } else {
            log.warn("MailSender is not JavaMailSenderImpl: {}", mailSender.getClass().getName());
        }

        log.info("From email: {}", fromEmail);
        log.info("App name: {}", appProperties.getName());
        log.info("=== END MAIL CONFIGURATION DEBUG ===");
    }

    private void debugMessage(final MimeMessage message) throws MessagingException {
        log.info("=== MESSAGE DEBUG ===");
        log.info("Message ID: {}", message.getMessageID());
        log.info("From: {}", java.util.Arrays.toString(message.getFrom()));
        log.info("To: {}", java.util.Arrays.toString(message.getAllRecipients()));
        log.info("Subject: {}", message.getSubject());
        log.info("Content Type: {}", message.getContentType());
        log.info("Size: {} bytes", message.getSize());

        final Session session = message.getSession();

        if (session != null) {
            log.info("Session debug: {}", session.getDebug());
            Properties sessionProps = session.getProperties();
            log.info("Session properties:");
            sessionProps.forEach((key, value) -> log.info("  {}: {}", key, value));
        }

        log.info("=== END MESSAGE DEBUG ===");
    }

    private void verifyEmailSent(final MimeMessage message) {
        log.info("=== VERIFYING EMAIL SENT ===");

        try {
            final Session session = message.getSession();

            if (session != null) {
                final Transport transport = session.getTransport("smtp");
                log.info("Transport class: {}", transport.getClass().getName());
                log.info("Transport connected: {}", transport.isConnected());
            }
        } catch (Exception e) {
            log.warn("Could not verify transport status", e);
        }

        log.info("=== END VERIFICATION ===");
    }

    public void sendTestEmail(final String toEmail) {
        log.info("=== SENDING TEST EMAIL ===");

        try {
            final MimeMessage message = mailSender.createMimeMessage();
            final MimeMessageHelper helper = new MimeMessageHelper(message, false, "UTF-8");

            helper.setFrom(fromEmail);
            helper.setTo(toEmail);
            helper.setSubject("Test Email - " + LocalDateTime.now());
            helper.setText("This is a test email sent at " + LocalDateTime.now(), false);

            log.info("Sending simple test email...");
            mailSender.send(message);
            log.info("Test email sent successfully");
        } catch (Exception e) {
            log.error("Test email failed", e);
            throw new RuntimeException("Test email failed", e);
        }
    }

    public void sendSecurityAlert(final String toEmail, final String alertType, final String details, final String clientIp) {
        if (!appProperties.getEmail().isSecurityAlertsEnabled()) {
            return;
        }

        try {
            final MimeMessage message = mailSender.createMimeMessage();
            final MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

            helper.setFrom(fromEmail, appProperties.getName() + " Security");
            helper.setTo(toEmail);
            helper.setSubject("🚨 Security Alert - " + appProperties.getName());

            final String htmlContent = buildSecurityAlertHtml(alertType, details, clientIp);
            helper.setText(htmlContent, true);

            mailSender.send(message);

            log.info("Security alert email sent to: {} for: {}", SecurityUtil.maskEmail(toEmail), alertType);
        } catch (Exception e) {
            log.error("Failed to send security alert to: {}", SecurityUtil.maskEmail(toEmail), e);
        }
    }

    private String buildWelcomeEmailHtml(final String clientIp) {
        final LocalDateTime now = LocalDateTime.now();
        final String formattedTime = now.format(DateTimeFormatter.ofPattern("MMM dd, yyyy 'at' HH:mm"));
        final String appName = appProperties.getName();
        final String supportEmail = appProperties.getSupport().getEmail();

        return String.format("""
                <!DOCTYPE html>
                <html>
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <title>Welcome</title>
                    <style>
                        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }
                        .container { max-width: 600px; margin: 0 auto; background: white; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
                        .header { background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%); color: white; padding: 30px; text-align: center; }
                        .content { padding: 30px; }
                        .welcome-box { background: #f0f9ff; border: 2px solid #0ea5e9; border-radius: 8px; padding: 20px; text-align: center; margin: 20px 0; }
                        .footer { background: #f8f9fa; padding: 20px; text-align: center; color: #666; font-size: 14px; }
                        .features { background: #f8fdf8; border: 1px solid #10b981; border-radius: 6px; padding: 15px; margin: 20px 0; }
                    </style>
                </head>
                <body>
                    <div class="container">
                        <div class="header">
                            <h1>🎉 Welcome to %s!</h1>
                            <p>Your secure password vault is ready</p>
                        </div>
                        <div class="content">
                            <h2>Hello and welcome!</h2>
                            <p>Your account has been successfully created and you're ready to start securing your passwords!</p>
                            
                            <div class="welcome-box">
                                <h3>🔐 Your Vault is Ready!</h3>
                                <p>You can now start generating and storing secure passwords. Everything is encrypted with your master password that only you know.</p>
                            </div>
                            
                            <div class="features">
                                <h3>🚀 What you can do:</h3>
                                <ul style="text-align: left; margin: 10px 0; padding-left: 20px;">
                                    <li><strong>Generate secure passwords</strong> with customizable options</li>
                                    <li><strong>Store unlimited passwords</strong> safely encrypted</li>
                                    <li><strong>Access from anywhere</strong> with your email and master password</li>
                                    <li><strong>Zero-knowledge security</strong> - we can't see your passwords</li>
                                </ul>
                            </div>
                            
                            <h3>🔒 Security Information</h3>
                            <p><strong>Account created:</strong> %s<br>
                               <strong>IP Address:</strong> %s<br>
                               <strong>Next steps:</strong> Log in and start adding your passwords!</p>
                               
                            <p style="background: #fff3cd; border: 1px solid #ffeaa7; border-radius: 6px; padding: 15px; color: #856404;">
                                <strong>🛡️ Security Note:</strong> If you didn't create this account, please contact us immediately at %s
                            </p>
                        </div>
                        <div class="footer">
                            <p>Thank you for choosing %s for your password security!</p>
                            <p>Need help? Contact us at %s</p>
                            <p><strong>%s - Secure • Private • Encrypted</strong></p>
                        </div>
                    </div>
                </body>
                </html>
                """, appName, formattedTime, clientIp, supportEmail, appName, supportEmail, appName);
    }

    /**
     * Builds HTML content for verification code email
     */
    private String buildVerificationEmailHtml(final String code) {
        final LocalDateTime now = LocalDateTime.now();
        final String formattedTime = now.format(DateTimeFormatter.ofPattern("MMM dd, yyyy 'at' HH:mm"));

        int expiryMinutes = appProperties.getVerification().getCode().getExpiry().getMinutes();

        final String expiryTime = now.plusMinutes(expiryMinutes).format(DateTimeFormatter.ofPattern("HH:mm"));

        final String appName = appProperties.getName();
        final String supportEmail = appProperties.getSupport().getEmail();

        return String.format("""
                <!DOCTYPE html>
                <html>
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <title>Verification Code</title>
                    <style>
                        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }
                        .container { max-width: 600px; margin: 0 auto; background: white; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
                        .header { background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%); color: white; padding: 30px; text-align: center; }
                        .content { padding: 30px; }
                        .code-box { background: #f8f9fa; border: 2px solid #667eea; border-radius: 8px; padding: 20px; text-align: center; margin: 20px 0; }
                        .code { font-size: 32px; font-weight: bold; color: #667eea; letter-spacing: 8px; font-family: 'Courier New', monospace; }
                        .footer { background: #f8f9fa; padding: 20px; text-align: center; color: #666; font-size: 14px; }
                        .warning { background: #fff3cd; border: 1px solid #ffeaa7; border-radius: 6px; padding: 15px; margin: 20px 0; color: #856404; }
                    </style>
                </head>
                <body>
                    <div class="container">
                        <div class="header">
                            <h1>🔐 %s</h1>
                            <p>Your secure verification code</p>
                        </div>
                        <div class="content">
                            <h2>Hello!</h2>
                            <p>You requested access to your password vault. Use the verification code below to complete your login:</p>
                            
                            <div class="code-box">
                                <div class="code">%s</div>
                            </div>
                            
                            <div class="warning">
                                <strong>⚠️ Security Notice:</strong>
                                <ul style="margin: 10px 0; padding-left: 20px;">
                                    <li>This code expires in %d minutes</li>
                                    <li>Never share this code with anyone</li>
                                    <li>We will never ask for this code via phone or email</li>
                                    <li>If you didn't request this code, please ignore this email</li>
                                </ul>
                            </div>
                            
                            <p>For your security, this code can only be used once and will expire at <strong>%s</strong>.</p>
                        </div>
                        <div class="footer">
                            <p>This email was sent on %s</p>
                            <p>If you need help, contact us at %s</p>
                            <p><strong>%s - Secure • Private • Encrypted</strong></p>
                        </div>
                    </div>
                </body>
                </html>
                """, appName, code, expiryMinutes, expiryTime, formattedTime, supportEmail, appName);
    }

    /**
     * Builds HTML content for security alert email
     */
    private String buildSecurityAlertHtml(final String alertType, final String details, final String clientIp) {
        final LocalDateTime now = LocalDateTime.now();
        final String formattedTime = now.format(DateTimeFormatter.ofPattern("MMM dd, yyyy 'at' HH:mm"));

        final String appName = appProperties.getName();
        final String supportEmail = appProperties.getSupport().getEmail();

        return String.format("""
                <!DOCTYPE html>
                <html>
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <title>Security Alert</title>
                    <style>
                        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }
                        .container { max-width: 600px; margin: 0 auto; background: white; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
                        .header { background: linear-gradient(135deg, #ef4444 0%%, #dc2626 100%%); color: white; padding: 30px; text-align: center; }
                        .content { padding: 30px; }
                        .alert-box { background: #fef2f2; border: 2px solid #ef4444; border-radius: 8px; padding: 20px; margin: 20px 0; }
                        .footer { background: #f8f9fa; padding: 20px; text-align: center; color: #666; font-size: 14px; }
                    </style>
                </head>
                <body>
                    <div class="container">
                        <div class="header">
                            <h1>🚨 Security Alert</h1>
                            <p>%s</p>
                        </div>
                        <div class="content">
                            <h2>Security Event Detected</h2>
                            <p>We detected unusual activity on your account that requires your attention.</p>
                            
                            <div class="alert-box">
                                <strong>Alert Type:</strong> %s<br><br>
                                <strong>Details:</strong> %s<br><br>
                                <strong>IP Address:</strong> %s<br><br>
                                <strong>Time:</strong> %s
                            </div>
                            
                            <h3>Recommended Actions:</h3>
                            <ul>
                                <li>Review your recent account activity</li>
                                <li>Change your master password if you suspect unauthorized access</li>
                                <li>Log out of all sessions and log back in securely</li>
                                <li>Contact support if you notice any suspicious activity</li>
                            </ul>
                        </div>
                        <div class="footer">
                            <p>If you have questions, contact us at %s</p>
                            <p><strong>%s Security Team</strong></p>
                        </div>
                    </div>
                </body>
                </html>
                """, appName, alertType, details, clientIp, formattedTime, supportEmail, appName);
    }
}