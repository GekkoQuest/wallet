package quest.gekko.wallet.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class InfoController {

    @GetMapping("/terms")
    public String termsPage() {
        return "terms";
    }

    @GetMapping("/privacy")
    public String privacyPage() {
        return "privacy";
    }

}