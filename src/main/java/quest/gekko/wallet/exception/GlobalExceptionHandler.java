package quest.gekko.wallet.exception;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.ConstraintViolation;
import jakarta.validation.ConstraintViolationException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.support.DefaultMessageSourceResolvable;
import org.springframework.http.HttpStatus;
import org.springframework.ui.Model;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import quest.gekko.wallet.util.MessageConstants;
import quest.gekko.wallet.util.SecurityUtil;

@ControllerAdvice
@Slf4j
public class GlobalExceptionHandler {

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
        return "redirect:/dashboard";
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
        return "redirect:/dashboard";
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
        return "redirect:/dashboard";
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
        return "redirect:/dashboard";
    }

    @ExceptionHandler(SecurityException.class)
    @ResponseStatus(HttpStatus.FORBIDDEN)
    public String handleSecurityException(
            final SecurityException e,
            final RedirectAttributes redirectAttributes,
            final HttpServletRequest request) {
        log.error("Security exception from IP {}: {}", getClientIp(request), e.getMessage());
        redirectAttributes.addFlashAttribute("error", MessageConstants.UNAUTHORIZED_ACCESS);
        return "redirect:/dashboard";
    }

    @ExceptionHandler(Exception.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public String handleGenericException(
            final Exception e,
            final Model model,
            final HttpServletRequest request) {
        log.error("Unexpected error from IP {}: {}", getClientIp(request), e.getMessage(), e);
        model.addAttribute("error", MessageConstants.UNEXPECTED_ERROR);
        return "error";
    }

    private String getClientIp(final HttpServletRequest request) {
        return SecurityUtil.getClientIpAddress(request);
    }
}