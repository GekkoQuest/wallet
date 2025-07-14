package quest.gekko.wallet.common.config.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Data
@ConfigurationProperties(prefix = "app")
public class ApplicationProperties {

    private String name = "Wallet";
    private Support support = new Support();
    private Verification verification = new Verification();
    private Security security = new Security();
    private Vault vault = new Vault();
    private Email email = new Email();
    private Cloudflare cloudflare = new Cloudflare();

    @Data
    public static class Support {
        private String email = "john@gekko.quest";
    }

    @Data
    public static class Verification {
        private Code code = new Code();
        private int maxAttempts = 5;

        @Data
        public static class Code {
            private int length = 6;
            private Expiry expiry = new Expiry();

            @Data
            public static class Expiry {
                private int minutes = 10;
            }
        }
    }

    @Data
    public static class Security {
        private RateLimit rateLimit = new RateLimit();
        private Session session = new Session();
        private Audit audit = new Audit();
        private boolean ipTrackingEnabled = true;
        private FailedAttempts failedAttempts = new FailedAttempts();
        private AccountLock accountLock = new AccountLock();
        private Cors cors = new Cors();
        private Alerts alerts = new Alerts();

        @Data
        public static class RateLimit {
            private EmailSend emailSend = new EmailSend();
            private CodeVerify codeVerify = new CodeVerify();

            @Data
            public static class EmailSend {
                private int perHour = 10;
                private int perMinute = 3;
            }

            @Data
            public static class CodeVerify {
                private int perHour = 20;
                private int perMinute = 5;
            }
        }

        @Data
        public static class Session {
            private int maxAgeHours = 24;
            private int maxConcurrent = 3;
        }

        @Data
        public static class Audit {
            private boolean enabled = true;
        }

        @Data
        public static class FailedAttempts {
            private int max = 5;
            private int maxVerificationAttempts = 5;
            private int maxUnlockAttempts = 5;
        }

        @Data
        public static class AccountLock {
            private int durationMinutes = 30;
        }

        @Data
        public static class Cors {
            private String allowedOrigins = "https://wallet.gekko.quest,http://localhost:8080";
            private String allowedMethods = "GET,POST";
            private String allowedHeaders = "*";
            private boolean allowCredentials = true;
        }

        @Data
        public static class Alerts {
            private boolean enabled = true;
            private boolean sendOnFailedLogin = true;
            private boolean sendOnNewIpLogin = true;
            private boolean sendOnRateLimit = true;
            private boolean sendOnVaultBreach = true;
            private boolean sendOnAccountCreation = true;
            private boolean sendOnMultipleFailedUnlocks = true;
            private int failedAttemptsThreshold = 3;
            private int rateLimitThreshold = 5;
            private int unlockAttemptsThreshold = 5;
        }
    }

    @Data
    public static class Vault {
        private int maxPasswordsPerUser = 1000;
        private int maxPasswordNameLength = 100;
        private int maxUsernameLength = 200;
        private Security security = new Security();

        @Data
        public static class Security {
            private int maxFailedUnlockAttempts = 5;
            private int unlockAttemptWindowMinutes = 15;
            private boolean alertOnUnauthorizedAccess = true;
            private boolean alertOnVaultLimitReached = true;
        }
    }

    @Data
    public static class Email {
        private Verification verification = new Verification();
        private boolean securityAlertsEnabled = true;
        private SecurityAlerts securityAlerts = new SecurityAlerts();

        @Data
        public static class Verification {
            private Template template = new Template();

            @Data
            public static class Template {
                private boolean enabled = true;
            }
        }

        @Data
        public static class SecurityAlerts {
            private boolean enabled = true;
            private boolean includeIpAddress = true;
            private boolean includeUserAgent = false;
            private boolean includeTimestamp = true;
            private String fromName = "Security Team";
            private Templates templates = new Templates();

            @Data
            public static class Templates {
                private boolean useHtmlTemplates = true;
                private boolean includeActionableAdvice = true;
                private boolean includeSupportContact = true;
            }
        }
    }

    @Data
    public static class Cloudflare {
        private boolean enabled = true;
    }
}