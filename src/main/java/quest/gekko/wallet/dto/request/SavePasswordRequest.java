package quest.gekko.wallet.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class SavePasswordRequest {
    @NotBlank(message = "Password name is required")
    @Size(max = 100, message = "Password name cannot exceed 100 characters")
    private String name;

    @NotBlank(message = "Encrypted password data is required")
    private String encrypted;

    @NotBlank(message = "Initialization vector is required")
    private String iv;

    @NotBlank(message = "Salt is required")
    private String salt;
}
