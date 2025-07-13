package quest.gekko.wallet.vault.dto.request;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class EditPasswordRequest {
    @NotBlank(message = "Password ID is required")
    private String id;

    @NotBlank(message = "Encrypted password data is required")
    private String encrypted;

    @NotBlank(message = "Initialization vector is required")
    private String iv;

    @NotBlank(message = "Salt is required")
    private String salt;
}