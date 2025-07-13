package quest.gekko.wallet.common.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import quest.gekko.wallet.security.interceptor.SecurityInterceptor;

@Configuration
@RequiredArgsConstructor
public class WebConfig implements WebMvcConfigurer {
    private final SecurityInterceptor securityInterceptor;

    @Override
    public void addInterceptors(final InterceptorRegistry registry) {
        registry.addInterceptor(securityInterceptor)
                .addPathPatterns("/dashboard", "/generate", "/edit", "/delete", "/vault/**")
                .excludePathPatterns("/", "/send-code", "/verify", "/logout",
                        "/css/**", "/static/js/**", "/images/**",
                        "/terms", "/privacy", "/error/**", "/debug/**");
    }
}