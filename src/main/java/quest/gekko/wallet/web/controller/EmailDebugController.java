package quest.gekko.wallet.web.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.JavaMailSenderImpl;
import org.springframework.web.bind.annotation.*;
import quest.gekko.wallet.common.email.service.EmailService;

import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

@RestController
@RequestMapping("/debug")
@RequiredArgsConstructor
public class EmailDebugController {

    private final EmailService emailService;
    private final JavaMailSender mailSender;
    private final Environment environment;

    @Value("${spring.mail.username}")
    private String fromEmail;

    @GetMapping("/email-config")
    public Map<String, Object> getEmailConfig() {
        final Map<String, Object> config = new HashMap<>();

        config.put("spring.mail.host", environment.getProperty("spring.mail.host"));
        config.put("spring.mail.port", environment.getProperty("spring.mail.port"));
        config.put("spring.mail.username", environment.getProperty("spring.mail.username"));
        config.put("spring.mail.password", environment.getProperty("spring.mail.password") != null ? "SET" : "NOT_SET");
        config.put("fromEmail", fromEmail);

        if (mailSender instanceof JavaMailSenderImpl javaMailSender) {
            final Map<String, Object> senderConfig = new HashMap<>();
            senderConfig.put("host", javaMailSender.getHost());
            senderConfig.put("port", javaMailSender.getPort());
            senderConfig.put("username", javaMailSender.getUsername());
            senderConfig.put("password", javaMailSender.getPassword() != null ? "SET" : "NOT_SET");
            senderConfig.put("protocol", javaMailSender.getProtocol());
            senderConfig.put("defaultEncoding", javaMailSender.getDefaultEncoding());

            final Properties props = javaMailSender.getJavaMailProperties();
            final Map<String, Object> propsMap = new HashMap<>();
            props.forEach((key, value) -> propsMap.put(key.toString(), value));
            senderConfig.put("javaMailProperties", propsMap);

            config.put("mailSender", senderConfig);
        }

        return config;
    }

    @PostMapping("/test-email")
    public Map<String, String> testEmail(@RequestParam final String to) {
        final Map<String, String> result = new HashMap<>();

        try {
            emailService.sendTestEmail(to);
            result.put("status", "SUCCESS");
            result.put("message", "Test email sent successfully");
        } catch (Exception e) {
            result.put("status", "ERROR");
            result.put("message", e.getMessage());
            result.put("error", e.getClass().getSimpleName());
        }

        return result;
    }

    @PostMapping("/test-connection")
    public Map<String, String> testConnection() {
        final Map<String, String> result = new HashMap<>();

        try {
            if (mailSender instanceof JavaMailSenderImpl javaMailSender) {
                javaMailSender.testConnection();
                result.put("status", "SUCCESS");
                result.put("message", "SMTP connection successful");
            } else {
                result.put("status", "ERROR");
                result.put("message", "MailSender is not JavaMailSenderImpl");
            }
        } catch (Exception e) {
            result.put("status", "ERROR");
            result.put("message", e.getMessage());
            result.put("error", e.getClass().getSimpleName());
        }

        return result;
    }
}