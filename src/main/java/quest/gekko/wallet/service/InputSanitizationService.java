package quest.gekko.wallet.service;

import org.springframework.stereotype.Service;

@Service
public class InputSanitizationService {

    private static final String EMAIL_REGEX = "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$";
    private static final String CODE_REGEX = "^[0-9]{6}$";
    private static final String NAME_REGEX = "^[a-zA-Z0-9\\s\\-_\\.]{1,100}$";

    public boolean isValidEmail(String email) {
        return email != null && email.matches(EMAIL_REGEX) && email.length() <= 320;
    }

    public boolean isValidVerificationCode(String code) {
        return code != null && code.matches(CODE_REGEX);
    }

    public boolean isValidPasswordName(String name) {
        return name != null && name.matches(NAME_REGEX) && name.trim().length() > 0;
    }

    public String sanitizeEmail(String email) {
        if (email == null) return null;
        return email.trim().toLowerCase();
    }

    public String sanitizePasswordName(String name) {
        if (name == null) return null;
        return name.trim().replaceAll("[<>\"'&]", ""); // Remove potential XSS characters
    }

    public String sanitizeCode(String code) {
        if (code == null) return null;
        return code.trim().replaceAll("[^0-9]", ""); // Only allow digits
    }
}