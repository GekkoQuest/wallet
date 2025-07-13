package quest.gekko.wallet.security.config;

import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@RequiredArgsConstructor
public class CloudflareConfig {

    @Bean
    @ConditionalOnProperty(name = "app.cloudflare.enabled", havingValue = "true", matchIfMissing = true)
    public CloudflareHeadersFilter cloudflareHeadersFilter() {
        return new CloudflareHeadersFilter();
    }
}