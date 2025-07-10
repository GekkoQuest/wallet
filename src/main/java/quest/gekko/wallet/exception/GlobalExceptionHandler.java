package quest.gekko.wallet.exception;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

@ControllerAdvice
@Slf4j
public class GlobalExceptionHandler {

    @ExceptionHandler(AuthenticationException.class)
    public String handleAuthenticationException(AuthenticationException e,
                                                Model model,
                                                HttpServletRequest request) {
        log.warn("Authentication exception from IP {}: {}", getClientIp(request), e.getMessage());
        model.addAttribute("error", "Authentication failed. Please try again.");
        return "login";
    }

    @ExceptionHandler(RateLimitExceededException.class)
    public String handleRateLimitException(RateLimitExceededException e,
                                           Model model,
                                           HttpServletRequest request) {
        log.warn("Rate limit exceeded from IP {}: {}", getClientIp(request), e.getMessage());
        model.addAttribute("error", "Too many requests. Please wait before trying again.");
        return "login";
    }

    @ExceptionHandler(VaultAccessException.class)
    public String handleVaultAccessException(VaultAccessException e,
                                             RedirectAttributes redirectAttributes,
                                             HttpServletRequest request) {
        log.warn("Vault access exception from IP {}: {}", getClientIp(request), e.getMessage());
        redirectAttributes.addFlashAttribute("error", "Access denied. Please check your permissions.");
        return "redirect:/dashboard";
    }

    @ExceptionHandler(InputValidationException.class)
    public String handleInputValidationException(InputValidationException e,
                                                 Model model,
                                                 HttpServletRequest request) {
        log.warn("Input validation exception from IP {}: {}", getClientIp(request), e.getMessage());
        model.addAttribute("error", "Invalid input provided. Please check your data.");
        return "login";
    }

    @ExceptionHandler(Exception.class)
    public String handleGenericException(Exception e,
                                         Model model,
                                         HttpServletRequest request) {
        log.error("Unexpected error from IP {}: {}", getClientIp(request), e.getMessage(), e);
        model.addAttribute("error", "An unexpected error occurred. Please try again.");
        return "error";
    }

    private String getClientIp(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}