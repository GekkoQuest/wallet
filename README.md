# Wallet

A personal password manager project built with Spring Boot as a learning exercise to explore web security and client-side encryption concepts.

**🔗 [View Live Demo](https://wallet.gekko.quest)**

## What Is This?

This project implements a **zero-knowledge password manager** where I experimented with keeping encrypted data on the server while ensuring the server never has access to unencrypted passwords. All sensitive operations happen client-side using the Web Crypto API.

### Client-Side Encryption
- **AES-GCM encryption** with 256-bit keys for password data
- **PBKDF2 key derivation** with 100,000 iterations and random salts
- **Unique IV per entry** so each encryption is different
- **Master password stays in browser** - never sent to the server

### Authentication Approach
- **Email-based login** using verification codes instead of passwords
- **Rate limiting** to prevent spam and brute force attempts
- **Session management** with timeouts and proper cleanup
- **Failed attempt tracking** with temporary lockouts

### Security Features
- **Input validation** to prevent XSS and injection attacks
- **Input sanitization** for all user data
- **Security audit logging** for tracking authentication events
- **Thread-safe rate limiting** with automatic cleanup
- **CORS configuration** for cross-origin protection

## Getting Started

### What You Need

- Java 21+
- MongoDB
- SMTP email server

### Running Locally

1. **Clone the project**
   ```bash
   git clone https://github.com/yourusername/password-manager.git
   cd password-manager
   ```

2. **Set up environment**
   ```bash
   export SPRING_DATA_MONGODB_URI=URI_HERE
   export SPRING_MAIL_HOST=HOST_HERE
   export SPRING_MAIL_PORT=PORT_HERE
   export SPRING_MAIL_USERNAME=USERNAME_HERE
   export SPRING_MAIL_PASSWORD=PASSWORD_HERE
   ```

3. **Start the application**
   ```bash
   ./mvnw spring-boot:run
   ```

4. **Try it out** at `http://localhost:8080`

## Configuration

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

## How It Works

### Backend
- **Spring Boot 3.5** with Spring Security for the foundation
- **MongoDB** for storing encrypted password data
- **Input validation** using annotations and custom validators
- **Transaction management** to keep data consistent

### Frontend
- **Vanilla JavaScript** with Web Crypto API for encryption
- **No external dependencies** to keep it simple
- **Session handling** with proper timeouts

### Encryption Process
1. User creates a master password (never leaves their browser)
2. PBKDF2 creates an encryption key with a random salt
3. Password data gets encrypted with AES-GCM and a unique IV
4. Only the encrypted data, IV, and salt go to the server
5. Server stores the encrypted blob without being able to decrypt it

### Security Measures
- **Session protection** against fixation attacks
- **Rate limiting** to prevent brute force attempts
- **Audit logging** for security events
- **Input cleaning** to prevent XSS attacks
- **Safe error handling** without leaking information

## Development

### Running in Dev Mode
```bash
export SPRING_PROFILES_ACTIVE=dev
./mvnw spring-boot:run
```

### Building
```bash
./mvnw clean package
java -jar target/wallet-0.0.1-SNAPSHOT.jar
```

## Project Structure

```
src/main/java/quest/gekko/wallet/
├── config/          # Security and app configuration
├── controller/      # Web controllers with security validation
├── entity/          # MongoDB entities
├── exception/       # Custom exception handling
├── repository/      # Data access layer
├── service/         # Business logic with security controls
└── util/           # Security utility functions

src/main/resources/
├── static/css/     # Frontend styles
├── templates/      # Thymeleaf templates
└── application.properties
```

## Important Notes

**This is a learning project** - I built it to better understand security concepts and improve my development skills.

### What it MAY be good for
- Learning about client-side encryption
- Understanding Spring Security
- Exploring secure coding practices
- Testing security features

### Not meant for
- Storing real sensitive passwords
- Production use without additional security measures
- Commercial or enterprise use

For real password storage, use established tools like Bitwarden, 1Password, or similar professionally audited solutions.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
