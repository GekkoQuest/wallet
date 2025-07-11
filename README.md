# Wallet

## Security Architecture

This project implements a **zero-knowledge architecture** where the server never has access to unencrypted password data. All sensitive operations are performed client-side using the Web Crypto API.

### Client-Side Encryption
- **AES-GCM encryption** with 256-bit keys for all password data
- **PBKDF2 key derivation** with 100,000 iterations and random salts
- **Unique IV per entry** ensuring each encryption is cryptographically unique
- **Master password never transmitted** - all encryption/decryption happens in the browser

### Authentication Security
- **Email-based passwordless authentication** using time-limited verification codes
- **Rate limiting** on both email sending and code verification attempts
- **Secure session management** with automatic timeouts and proper invalidation
- **Failed attempt tracking** with temporary account lockouts

### Input Security
- **Comprehensive input validation** preventing XSS and injection attacks
- **Input sanitization** for all user-provided data
- **Base64 validation** for encrypted data integrity
- **CSRF protection** through Spring Security

### Application Security
- **Security audit logging** for all authentication and password operations
- **IP address tracking** for suspicious activity detection
- **Thread-safe rate limiting** with automatic cleanup
- **Configurable CORS policies** for cross-origin protection

## Quick Start

### Prerequisites

- Java 21+
- MongoDB
- SMTP email server

### Installation

1. **Clone and setup**
   ```bash
   git clone https://github.com/yourusername/password-manager.git
   cd password-manager
   ```

2. **Environment variables**
   ```bash
   export SPRING_DATA_MONGODB_URI="mongodb://localhost:27017/wallet"
   export SPRING_MAIL_HOST="smtp.your-provider.com"
   export SPRING_MAIL_PORT="587"
   export SPRING_MAIL_USERNAME="your-email@domain.com"
   export SPRING_MAIL_PASSWORD="your-app-password"
   ```

3. **Run application**
   ```bash
   ./mvnw spring-boot:run
   ```

4. **Access at** `http://localhost:8080`

## Security Configuration

Key security settings in `application.properties`:

```properties
# Rate Limiting
app.security.rate-limit.email-send.per-hour=10
app.security.rate-limit.code-verify.per-hour=20

# Account Security
app.security.failed-attempts.max=5
app.security.account-lock.duration-minutes=30

# Session Security
server.servlet.session.timeout=30m
server.servlet.session.cookie.http-only=true
server.servlet.session.cookie.secure=true
server.servlet.session.cookie.same-site=strict
```

## Technical Implementation

### Backend Architecture
- **Spring Boot 3.5** with Spring Security for authentication and authorization
- **MongoDB** for encrypted password storage with proper indexing
- **Spring Data** repositories with custom security queries
- **Input validation** using JSR-303 annotations and custom validators
- **Transaction management** ensuring data consistency

### Frontend Security
- **Vanilla JavaScript** with Web Crypto API for encryption operations
- **No external dependencies** reducing attack surface
- **Content Security Policy** ready implementation
- **Secure session handling** with proper timeout management

### Encryption Flow
1. User enters master password (never transmitted)
2. PBKDF2 derives encryption key with random salt
3. Password data encrypted with AES-GCM and unique IV
4. Only encrypted data, IV, and salt sent to server
5. Server stores encrypted blob without decryption capability

### Security Measures
- **Session fixation protection** through proper session management
- **Brute force protection** via rate limiting and account lockouts
- **Audit trail** for all security-related operations
- **Input sanitization** preventing XSS and injection attacks
- **Error handling** without information leakage

## Development

### Running in Development
```bash
export SPRING_PROFILES_ACTIVE=dev
./mvnw spring-boot:run
```

### Building for Production
```bash
./mvnw clean package
java -jar target/wallet-0.0.1-SNAPSHOT.jar
```

### Security Testing
The application includes comprehensive security measures suitable for testing:
- Rate limiting validation
- Session security testing
- Input validation verification
- Encryption/decryption testing

## Project Structure

```
src/main/java/quest/gekko/wallet/
├── config/          # Security and application configuration
├── controller/      # Request handling with security validation
├── entity/          # MongoDB entities with proper indexing
├── exception/       # Custom security exceptions
├── repository/      # Secure data access layer
├── service/         # Business logic with security controls
└── util/           # Security utility functions

src/main/resources/
├── static/css/     # Frontend styling
├── templates/      # Secure Thymeleaf templates
└── application.properties
```

## Important Security Notice

**This is a demonstration project** designed to showcase secure coding practices and modern web security implementation.

### Educational Value
- Demonstrates client-side encryption techniques
- Shows proper Spring Security implementation
- Illustrates secure session management
- Examples of input validation and sanitization

### Production Considerations
For production use with real passwords, additional measures would be required:
- Professional security audit
- Hardware security modules (HSM)
- Multi-factor authentication
- Comprehensive backup and disaster recovery
- Security monitoring and alerting
- Regular penetration testing

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.