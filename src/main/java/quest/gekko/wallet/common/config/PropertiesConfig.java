package quest.gekko.wallet.common.config;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import quest.gekko.wallet.common.config.properties.ApplicationProperties;

@Configuration
@EnableConfigurationProperties(ApplicationProperties.class)
public class PropertiesConfig {
}
