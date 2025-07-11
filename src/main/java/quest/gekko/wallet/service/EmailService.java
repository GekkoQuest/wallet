package quest.gekko.wallet.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.JavaMailSenderImpl;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;
import quest.gekko.wallet.config.properties.ApplicationProperties;
import quest.gekko.wallet.exception.AuthenticationException;

import jakarta.mail.MessagingException;
import jakarta.mail.Transport;
import jakarta.mail.internet.MimeMessage;
import jakarta.mail.Session;
import quest.gekko.wallet.util.SecurityUtil;

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

    public void sendVerificationCode(String toEmail, String code) {
        log.info("=== EMAIL DEBUGGING START ===");
        log.info("Attempting to send verification code to: {}", SecurityUtil.maskEmail(toEmail));

        // Debug mail sender configuration
        debugMailConfiguration();

        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

            helper.setFrom(fromEmail, appProperties.getName());
            helper.setTo(toEmail);
            helper.setSubject("🔐 Your Security Code - " + appProperties.getName());

            String htmlContent = buildVerificationEmailHtml(code);
            helper.setText(htmlContent, true);

            // Debug the message before sending
            debugMessage(message);

            log.info("Calling mailSender.send()...");
            mailSender.send(message);
            log.info("mailSender.send() completed without exception");

            // Try to verify if email was actually sent
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

    private void debugMailConfiguration() {
        log.info("=== MAIL CONFIGURATION DEBUG ===");

        if (mailSender instanceof JavaMailSenderImpl javaMailSender) {
            log.info("Host: {}", javaMailSender.getHost());
            log.info("Port: {}", javaMailSender.getPort());
            log.info("Username: {}", javaMailSender.getUsername());
            log.info("Password: {}", javaMailSender.getPassword() != null ? "SET" : "NOT_SET");
            log.info("Default encoding: {}", javaMailSender.getDefaultEncoding());
            log.info("Protocol: {}", javaMailSender.getProtocol());

            Properties props = javaMailSender.getJavaMailProperties();
            log.info("JavaMail Properties:");
            props.forEach((key, value) -> log.info("  {}: {}", key, value));

            // Test connection
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

    private void debugMessage(MimeMessage message) throws MessagingException {
        log.info("=== MESSAGE DEBUG ===");
        log.info("Message ID: {}", message.getMessageID());
        log.info("From: {}", java.util.Arrays.toString(message.getFrom()));
        log.info("To: {}", java.util.Arrays.toString(message.getAllRecipients()));
        log.info("Subject: {}", message.getSubject());
        log.info("Content Type: {}", message.getContentType());
        log.info("Size: {} bytes", message.getSize());

        // Try to get the session
        Session session = message.getSession();
        if (session != null) {
            log.info("Session debug: {}", session.getDebug());
            Properties sessionProps = session.getProperties();
            log.info("Session properties:");
            sessionProps.forEach((key, value) -> log.info("  {}: {}", key, value));
        }

        log.info("=== END MESSAGE DEBUG ===");
    }

    private void verifyEmailSent(MimeMessage message) {
        log.info("=== VERIFYING EMAIL SENT ===");

        try {
            // Try to get transport information
            Session session = message.getSession();
            if (session != null) {
                Transport transport = session.getTransport("smtp");
                log.info("Transport class: {}", transport.getClass().getName());
                log.info("Transport connected: {}", transport.isConnected());
            }
        } catch (Exception e) {
            log.warn("Could not verify transport status", e);
        }

        log.info("=== END VERIFICATION ===");
    }

    // Add a test method to manually verify email sending
    public void sendTestEmail(String toEmail) {
        log.info("=== SENDING TEST EMAIL ===");

        try {
            // Create a simple test message
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, false, "UTF-8");

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

    public void sendSecurityAlert(String toEmail, String alertType, String details, String clientIp) {
        if (!appProperties.getEmail().isSecurityAlertsEnabled()) {
            return;
        }

        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

            helper.setFrom(fromEmail, appProperties.getName() + " Security");
            helper.setTo(toEmail);
            helper.setSubject("🚨 Security Alert - " + appProperties.getName());

            String htmlContent = buildSecurityAlertHtml(alertType, details, clientIp);
            helper.setText(htmlContent, true);

            mailSender.send(message);

            log.info("Security alert email sent to: {} for: {}", SecurityUtil.maskEmail(toEmail), alertType);

        } catch (Exception e) {
            log.error("Failed to send security alert to: {}", SecurityUtil.maskEmail(toEmail), e);
            // Don't throw exception for security alerts to avoid breaking the flow
        }
    }

    /**
     * Builds HTML content for verification code email
     */
    private String buildVerificationEmailHtml(String code) {
        LocalDateTime now = LocalDateTime.now();
        String formattedTime = now.format(DateTimeFormatter.ofPattern("MMM dd, yyyy 'at' HH:mm"));
        int expiryMinutes = appProperties.getVerification().getCode().getExpiry().getMinutes();
        String expiryTime = now.plusMinutes(expiryMinutes).format(DateTimeFormatter.ofPattern("HH:mm"));
        String appName = appProperties.getName();
        String supportEmail = appProperties.getSupport().getEmail();

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
    private String buildSecurityAlertHtml(String alertType, String details, String clientIp) {
        LocalDateTime now = LocalDateTime.now();
        String formattedTime = now.format(DateTimeFormatter.ofPattern("MMM dd, yyyy 'at' HH:mm"));
        String appName = appProperties.getName();
        String supportEmail = appProperties.getSupport().getEmail();

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