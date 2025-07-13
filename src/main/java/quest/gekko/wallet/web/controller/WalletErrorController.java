package quest.gekko.wallet.web.controller;

import jakarta.servlet.RequestDispatcher;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.web.servlet.error.ErrorController;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import quest.gekko.wallet.security.util.SecurityUtil;

@Controller
@Slf4j
public class WalletErrorController implements ErrorController {

    @RequestMapping("/error")
    public String handleError(final HttpServletRequest request, final Model model) {
        final Object status = request.getAttribute(RequestDispatcher.ERROR_STATUS_CODE);
        final String clientIp = SecurityUtil.getClientIpAddress(request);
        final String requestUri = (String) request.getAttribute(RequestDispatcher.ERROR_REQUEST_URI);

        if (status != null) {
            final int statusCode = Integer.parseInt(status.toString());

            log.warn("Error {} occurred for URI: {} from IP: {}", statusCode, requestUri, clientIp);

            model.addAttribute("statusCode", statusCode);
            model.addAttribute("requestUri", requestUri);

            return switch (statusCode) {
                case 404 -> {
                    model.addAttribute("error", "The page you're looking for doesn't exist.");
                    yield "error/404";
                }
                case 403 -> {
                    model.addAttribute("error", "You don't have permission to access this resource.");
                    yield "error/403";
                }
                case 500 -> {
                    model.addAttribute("error", "Internal server error. Please try again later.");
                    yield "error/500";
                }
                case 400 -> {
                    model.addAttribute("error", "Bad request. Please check your input and try again.");
                    yield "error";
                }
                case 429 -> {
                    model.addAttribute("error", "Too many requests. Please wait before trying again.");
                    yield "error";
                }
                default -> {
                    model.addAttribute("error", "An unexpected error occurred. Please try again.");
                    yield "error";
                }
            };
        }

        model.addAttribute("error", "An unexpected error occurred. Please try again.");
        log.error("Unknown error occurred for URI: {} from IP: {}", requestUri, clientIp);
        return "error";
    }
}