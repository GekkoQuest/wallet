package quest.gekko.wallet.common.exception;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.ConstraintViolation;
import jakarta.validation.ConstraintViolationException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.support.DefaultMessageSourceResolvable;
import org.springframework.http.HttpStatus;
import org.springframework.ui.Model;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.servlet.NoHandlerFoundException;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import org.springframework.web.servlet.resource.NoResourceFoundException;
import quest.gekko.wallet.authentication.exception.AuthenticationException;
import quest.gekko.wallet.common.constants.MessageConstants;
import quest.gekko.wallet.security.util.SecurityUtil;
import quest.gekko.wallet.vault.exception.VaultAccessException;
import quest.gekko.wallet.vault.exception.VaultException;

import java.util.Set;

@ControllerAdvice
@Slf4j
public class GlobalExceptionHandler {
    // Hacky way, but it'll do for now.
    private static final Set<String> POTENTIAL_BOT_INDICATORS = Set.of(
            ".php", ".asp", ".jsp",
            "wp-", "admin", "config", "setup", "install", "backup",
            "phpmyadmin", "xmlrpc", "karma.conf", "package.json",
            "composer.json", "main.yml", "docker-compose", "dockerfile",
            ".env", ".git", ".ssh", "cgi-bin", "getcpuutil",
            "helpers/", "scripts/", "uploads/", "robots.txt", "sitemap"
    );

    @ExceptionHandler(NoHandlerFoundException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public String handleNoHandlerFound(
            final NoHandlerFoundException e,
            final Model model,
            final HttpServletRequest request) {
        final String requestURI = request.getRequestURI();
        final String clientIp = getClientIp(request);

        if (isLikelyBotRequest(requestURI)) {
            log.debug("Bot/scanner request from IP {}: {} {}", clientIp, e.getHttpMethod(), requestURI);
        } else {
            log.info("Page not found from IP {}: {} {}", clientIp, e.getHttpMethod(), requestURI);
        }

        model.addAttribute("error", "The page you're looking for doesn't exist.");
        model.addAttribute("requestUri", requestURI);
        return "error/404";
    }

    @ExceptionHandler(NoResourceFoundException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public String handleNoResourceFound(
            final NoResourceFoundException e,
            final Model model,
            final HttpServletRequest request) {
        final String requestURI = request.getRequestURI();
        final String clientIp = getClientIp(request);

        if (isLikelyBotRequest(requestURI)) {
            log.debug("Resource not found from IP {}: {}", clientIp, requestURI);
        } else {
            log.info("Resource not found from IP {}: {}", clientIp, requestURI);
        }

        model.addAttribute("error", "The resource you're looking for doesn't exist.");
        model.addAttribute("requestUri", requestURI);
        return "error/404";
    }

    @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
    @ResponseStatus(HttpStatus.METHOD_NOT_ALLOWED)
    public String handleMethodNotSupported(
            final HttpRequestMethodNotSupportedException e,
            final Model model,
            final HttpServletRequest request) {
        log.debug("Method not supported from IP {}: {} {}", getClientIp(request), e.getMethod(), request.getRequestURI());
        model.addAttribute("error", "Method not allowed. Please use the correct request method.");
        return "error";
    }

    @ExceptionHandler(AuthenticationException.class)
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public String handleAuthenticationException(
            final AuthenticationException e,
            final Model model,
            final HttpServletRequest request) {
        log.warn("Authentication exception from IP {}: {}", getClientIp(request), e.getMessage());
        model.addAttribute("error", "Authentication failed. Please try again.");
        return "login";
    }

    @ExceptionHandler(RateLimitExceededException.class)
    @ResponseStatus(HttpStatus.TOO_MANY_REQUESTS)
    public String handleRateLimitException(
            final RateLimitExceededException e,
            final Model model,
            final HttpServletRequest request) {
        log.warn("Rate limit exceeded from IP {}: {}", getClientIp(request), e.getMessage());
        model.addAttribute("error", MessageConstants.RATE_LIMIT_EXCEEDED);
        return "login";
    }

    @ExceptionHandler(VaultAccessException.class)
    @ResponseStatus(HttpStatus.FORBIDDEN)
    public String handleVaultAccessException(
            final VaultAccessException e,
            final RedirectAttributes redirectAttributes,
            final HttpServletRequest request) {
        log.warn("Vault access exception from IP {}: {}", getClientIp(request), e.getMessage());
        redirectAttributes.addFlashAttribute("error", "Access denied. Please check your permissions.");
        return "redirect:/vault/dashboard";
    }

    @ExceptionHandler(VaultException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public String handleVaultException(final VaultException e, final RedirectAttributes redirectAttributes, final HttpServletRequest request) {
        log.warn("Vault exception from IP {} (type: {}): {}",
                getClientIp(request), e.getErrorType(), e.getMessage());

        final String errorMessage = switch (e.getErrorType()) {
            case LIMIT_EXCEEDED -> MessageConstants.VAULT_LIMIT_REACHED;
            case UNAUTHORIZED_ACCESS -> MessageConstants.UNAUTHORIZED_ACCESS;
            case VALIDATION_ERROR -> "Invalid data provided";
            case ENCRYPTION_ERROR -> "Encryption error occurred";
            case DATA_CORRUPTION -> "Data integrity error";
            case STORAGE_ERROR -> "Storage error occurred";
        };

        redirectAttributes.addFlashAttribute("error", errorMessage);
        return "redirect:/vault/dashboard";
    }

    @ExceptionHandler(InputValidationException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public String handleInputValidationException(
            final InputValidationException e,
            final Model model,
            final HttpServletRequest request) {
        log.warn("Input validation exception from IP {}: {}", getClientIp(request), e.getMessage());
        model.addAttribute("error", "Invalid input provided. Please check your data.");
        return "login";
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public String handleValidationException(
            final MethodArgumentNotValidException e,
            final RedirectAttributes redirectAttributes,
            final HttpServletRequest request) {
        log.warn("Validation exception from IP {}: {}", getClientIp(request), e.getMessage());

        final String errorMessage = e.getBindingResult().getFieldErrors().stream()
                .findFirst()
                .map(DefaultMessageSourceResolvable::getDefaultMessage)
                .orElse("Validation error occurred");

        redirectAttributes.addFlashAttribute("error", errorMessage);
        return "redirect:/vault/dashboard";
    }

    @ExceptionHandler(ConstraintViolationException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public String handleConstraintViolationException(
            final ConstraintViolationException e,
            final RedirectAttributes redirectAttributes,
            final HttpServletRequest request) {
        log.warn("Constraint violation from IP {}: {}", getClientIp(request), e.getMessage());

        final String errorMessage = e.getConstraintViolations().stream()
                .findFirst()
                .map(ConstraintViolation::getMessage)
                .orElse("Validation constraint violation");

        redirectAttributes.addFlashAttribute("error", errorMessage);
        return "redirect:/vault/dashboard";
    }

    @ExceptionHandler(SecurityException.class)
    @ResponseStatus(HttpStatus.FORBIDDEN)
    public String handleSecurityException(
            final SecurityException e,
            final RedirectAttributes redirectAttributes,
            final HttpServletRequest request) {
        log.error("Security exception from IP {}: {}", getClientIp(request), e.getMessage());
        redirectAttributes.addFlashAttribute("error", MessageConstants.UNAUTHORIZED_ACCESS);
        return "redirect:/vault/dashboard";
    }

    @ExceptionHandler(Exception.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public String handleGenericException(
            final Exception e,
            final Model model,
            final HttpServletRequest request) {
        final String requestURI = request.getRequestURI();
        final String clientIp = getClientIp(request);

        if (isLikelyBotRequest(requestURI)) {
            log.debug("Bot/scanner request to non-existent resource from IP {}: {}", clientIp, requestURI);
            model.addAttribute("error", "The resource you're looking for doesn't exist.");
            return "error/404";
        }

        log.error("Unexpected error from IP {}: {}", clientIp, e.getMessage(), e);
        model.addAttribute("error", MessageConstants.UNEXPECTED_ERROR);
        return "error";
    }

    private String getClientIp(final HttpServletRequest request) {
        return SecurityUtil.getClientIpAddress(request);
    }

    private boolean isLikelyBotRequest(final String requestURI) {
        if (requestURI == null) return false;

        final String uri = requestURI.toLowerCase();

        return POTENTIAL_BOT_INDICATORS.stream().anyMatch(uri::contains) ||
                (uri.contains("test") && (uri.contains(".js") || uri.contains(".json")));
    }
}