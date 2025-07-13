# Wallet

A personal password manager project built with Spring Boot as a learning exercise to explore web security and client-side encryption concepts.

**🔗 [View Live Demo](https://wallet.gekko.quest)**

## What Is This?

This project implements a **zero-knowledge password manager** where I experimented with keeping encrypted data on the server while ensuring the server never has access to unencrypted passwords. All sensitive operations happen client-side using the Web Crypto API.

### Core Architecture
- **Zero-knowledge design** - Server cannot decrypt your passwords
- **Client-side encryption** using Web Crypto API with AES-GCM 256-bit encryption
- **Email-based authentication** - No traditional passwords, uses secure verification codes
- **Session-based security** with automatic timeouts and activity tracking
- **Rate limiting** and security audit logging throughout

## Security Features

### Encryption & Key Management
- **AES-GCM encryption** with 256-bit keys for maximum security
- **PBKDF2 key derivation** with 100,000 iterations and random salts
- **Unique IV per entry** ensuring each encryption is cryptographically unique
- **Master password isolation** - Never transmitted or stored on server
- **Secure key timeout** - Automatic session expiration for security

### Authentication System
- **Passwordless login** using time-limited verification codes
- **Email-based verification** with HTML templates and security alerts
- **Rate limiting** on both email sending and code verification attempts
- **Account lockout protection** with configurable failed attempt thresholds
- **Session security** with anti-fixation and secure cookie handling
- **Activity tracking** with automatic session extension and timeout warnings

### Input Validation & Protection
- **Input sanitization** preventing XSS and injection attacks
- **Server-side validation** with detailed error handling and logging
- **CORS protection** with configurable origin policies
- **Security headers** including HSTS, frame options, and content type protection
- **Cloudflare integration** for proxy header handling and DDoS protection

### Audit & Monitoring
- **Security event logging** for all authentication and vault access
- **Failed attempt tracking** with IP-based monitoring
- **Suspicious activity detection** and automatic alerts
- **Rate limit monitoring** with detailed violation logging

## Vault Management Features

### Password Operations
- **Secure password generation** with customizable character sets and length
- **Real-time password strength analysis** with detailed requirement checking
- **CRUD operations** - Create, edit, delete, and search password entries
- **Bulk operations** with transaction safety and rollback protection (Soon)
- **Usage analytics** - Track access patterns and vault statistics (Soon)

### User Experience
- **Responsive design** with mobile-first approach and modern UI
- **Copy-to-clipboard** functionality with automatic clearing
- **Show/hide passwords** with secure visibility toggling
- **Search functionality** with sanitized input and performance optimization (Soon)
- **Real-time statistics** showing vault usage and limits (Soon)

### Data Management
- **MongoDB integration** with indexed collections for performance
- **Automatic cleanup** of expired verification codes and sessions
- **Vault limits** with configurable password storage quotas (1000 per user)

## Technical Implementation

### Backend (Spring Boot 3.5)
- **Spring Security** with custom authentication and session management
- **MongoDB** with optimized queries and proper indexing
- **Email service** with SMTP configuration and template rendering
- **Rate limiting service** with thread-safe implementation and cleanup
- **Input sanitization service** with validation rules
- **Async processing** for email sending and background tasks

### Frontend (JavaScript)
- **Web Crypto API** integration for client-side encryption/decryption
- **Secure key management** with in-memory storage and timeout handling
- **Progressive enhancement** with fallbacks for older browsers
- **Real-time validation** and user feedback systems
- **Modern CSS** with CSS Grid, Flexbox, and custom properties

## Configuration & Deployment

### Environment Support
```properties
# Production-ready configuration
SPRING_DATA_MONGODB_URI=mongodb://localhost:27017/wallet
SPRING_MAIL_HOST=smtp.example.com
SPRING_MAIL_USERNAME=notifications@example.com
CORS_ALLOWED_ORIGINS=https://yourdomain.com
CLOUDFLARE_ENABLED=true
```

### Security Configuration
```properties
# Rate limiting (per hour/minute)
app.security.rate-limit.email-send.per-hour=10
app.security.rate-limit.code-verify.per-hour=20

# Account protection
app.security.failed-attempts.max=5
app.security.account-lock.duration-minutes=30

# Session security
server.servlet.session.timeout=30m
server.servlet.session.cookie.secure=true
server.servlet.session.cookie.same-site=lax
```

### Docker Deployment
```bash
# Build and run with Docker Compose
docker-compose up --build

# Or build manually
docker build -t wallet .
docker run -p 8080:8080 --env-file .env wallet
```

## Getting Started

### Prerequisites
- Java 21+
- MongoDB 4.4+
- SMTP email server (Gmail, SendGrid, etc.)

### Quick Setup

1. **Clone and configure**
   ```bash
   git clone https://github.com/yourusername/wallet.git
   cd wallet
   cp .env.example .env
   # Edit .env with your configuration
   ```

2. **Run locally**
   ```bash
   ./mvnw spring-boot:run
   ```

3. **Access the application**
   - Open `http://localhost:8080`
   - Enter your email to receive a verification code
   - Create your master password (client-side only)
   - Start managing passwords securely

### Development Mode
```bash
export SPRING_PROFILES_ACTIVE=dev
export CLOUDFLARE_ENABLED=false
./mvnw spring-boot:run -Dspring-boot.run.arguments="--debug"
```

## API Endpoints

### Authentication
- `POST /send-code` - Request verification code
- `POST /verify` - Verify code and authenticate
- `GET /logout` - Terminate session

### Vault Management
- `GET /dashboard` - Main vault interface
- `POST /generate` - Save new password
- `POST /edit` - Update existing password
- `POST /delete` - Remove password entry
- `GET /vault/search` - Search vault entries
- `GET /vault/statistics` - Get usage statistics

### Utilities
- `GET /debug/email-config` - Email configuration check
- `POST /debug/test-email` - Send test email

## Project Structure

```
src/main/java/quest/gekko/wallet/
├── authentication/      # Email-based authentication and verification
│   ├── controller/AuthenticationController.java
│   ├── service/
│   │   ├── AuthenticationService.java
│   │   └── EmailService.java
│   ├── entity/VerificationCode.java
│   ├── repository/VerificationCodeRepository.java
│   ├── exception/AuthenticationException.java
│   └── dto/request/
├── user/               # User entity and repository
│   ├── entity/User.java
│   └── repository/UserRepository.java
├── vault/              # Password vault management
│   ├── controller/VaultController.java
│   ├── service/PasswordManagementService.java
│   ├── entity/PasswordEntry.java
│   ├── repository/PasswordEntryRepository.java
│   ├── dto/
│   │   ├── request/
│   │   └── response/
│   └── exception/
├── audit/              # Security event logging and monitoring
│   └── service/SecurityAuditService.java
├── ratelimit/          # Rate limiting functionality
│   └── service/RateLimitingService.java
├── validation/         # Input validation and sanitization
│   └── service/InputSanitizationService.java
├── security/           # Core security infrastructure
│   ├── config/
│   │   ├── SecurityConfig.java
│   │   └── CloudflareConfig.java
│   ├── session/service/SessionManagementService.java
│   ├── encryption/util/EncryptionUtil.java
│   ├── interceptor/SecurityInterceptor.java
│   └── util/SecurityUtil.java
└── common/             # Shared utilities and configuration
    ├── config/
    ├── constants/
    ├── controller/     # Utility controllers (debug, info, error)
    ├── exception/      # Global exception handling
    └── util/

src/main/resources/
├── static/css/
├── templates/
└── application.properties
```

## Important Notes

This is a **student project** I built to learn about web security and encryption. While I tried to implement security features properly, I'm still learning and this shouldn't be considered a reference implementation.

### ⚠️ Not intended for:
- Storing real passwords or sensitive data
- Production use or commercial deployment
- Use by others as a secure password manager
- Reference as a "best practices" implementation

### 🔒 For actual password management:
Use established solutions like **Bitwarden**, **1Password**, or **Dashlane** that have:
- Professional security audits and certifications
- Proper enterprise support and guarantees
- Teams of security experts maintaining them

## Contributing

This is a personal learning project, but if you spot any issues or have suggestions for improvement, feel free to open an issue or reach out.

## License

AGPL-3.0 License - see [LICENSE](LICENSE) file for details.
