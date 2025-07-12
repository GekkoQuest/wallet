package quest.gekko.wallet.util;

import lombok.experimental.UtilityClass;
import org.springframework.ui.Model;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

@UtilityClass
public class ResponseUtil {

    public static void addSuccessMessage(final RedirectAttributes redirectAttributes, final String message) {
        redirectAttributes.addFlashAttribute("success", message);
    }

    public static void addErrorMessage(final RedirectAttributes redirectAttributes, final String message) {
        redirectAttributes.addFlashAttribute("error", message);
    }

    public static void addSuccessMessage(final Model model, final String message) {
        model.addAttribute("success", message);
    }

    public static void addErrorMessage(final Model model, final String message) {
        model.addAttribute("error", message);
    }

    public static void addPasswordSavedSuccess(final RedirectAttributes redirectAttributes) {
        addSuccessMessage(redirectAttributes, MessageConstants.PASSWORD_SAVED_SUCCESS);
    }

    public static void addPasswordUpdatedSuccess(final RedirectAttributes redirectAttributes) {
        addSuccessMessage(redirectAttributes, MessageConstants.PASSWORD_UPDATED_SUCCESS);
    }

    public static void addPasswordDeletedSuccess(final RedirectAttributes redirectAttributes) {
        addSuccessMessage(redirectAttributes, MessageConstants.PASSWORD_DELETED_SUCCESS);
    }

    public static void addUnauthorizedAccessError(final RedirectAttributes redirectAttributes) {
        addErrorMessage(redirectAttributes, MessageConstants.UNAUTHORIZED_ACCESS);
    }

    public static void addUnexpectedError(final RedirectAttributes redirectAttributes) {
        addErrorMessage(redirectAttributes, MessageConstants.UNEXPECTED_ERROR);
    }

    public static void addInvalidEmailError(final Model model) {
        addErrorMessage(model, MessageConstants.INVALID_EMAIL);
    }

    public static void addRateLimitError(final Model model) {
        addErrorMessage(model, MessageConstants.RATE_LIMIT_EXCEEDED);
    }
}