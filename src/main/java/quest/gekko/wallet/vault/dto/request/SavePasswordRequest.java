package quest.gekko.wallet.vault.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class SavePasswordRequest {
    @NotBlank(message = "Service name is required")
    @Size(max = 100, message = "Service name cannot exceed 100 characters")
    private String serviceName;

    @Size(max = 200, message = "Username cannot exceed 200 characters")
    private String username;

    @NotBlank(message = "Encrypted password data is required")
    private String encrypted;

    @NotBlank(message = "Initialization vector is required")
    private String iv;

    @NotBlank(message = "Salt is required")
    private String salt;
}