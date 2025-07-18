package quest.gekko.wallet.common.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class InfoController {

    @GetMapping("/terms")
    public String termsPage() {
        return "legal/privacy";
    }

    @GetMapping("/privacy")
    public String privacyPage() {
        return "legal/terms";
    }

}