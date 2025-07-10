package quest.gekko.wallet.config;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import quest.gekko.wallet.config.properties.ApplicationProperties;

@Configuration
@EnableConfigurationProperties(ApplicationProperties.class)
public class PropertiesConfig {
}
