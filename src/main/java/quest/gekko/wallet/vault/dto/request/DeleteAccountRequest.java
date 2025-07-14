package quest.gekko.wallet.vault.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.Data;

@Data
public class DeleteAccountRequest {
    @NotBlank(message = "Confirmation text is required")
    @Pattern(regexp = "DELETE", message = "Must type 'DELETE' to confirm")
    private String confirmationText;
}