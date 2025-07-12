package quest.gekko.wallet.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter;
import org.springframework.security.web.session.HttpSessionEventPublisher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import quest.gekko.wallet.config.properties.ApplicationProperties;

import java.time.Duration;
import java.util.Arrays;
import java.util.List;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final ApplicationProperties applicationProperties;
    private final Environment environment;

    @Bean
    public SecurityFilterChain securityFilterChain(final HttpSecurity http) throws Exception {
        return http
                .sessionManagement(session -> {
                    session.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED);
                    session.maximumSessions(applicationProperties.getSecurity().getSession().getMaxConcurrent())
                            .maxSessionsPreventsLogin(false);
                    session.invalidSessionUrl("/");
                })

                .headers(headers -> {
                    headers.frameOptions(HeadersConfigurer.FrameOptionsConfig::deny);
                    headers.contentTypeOptions(Customizer.withDefaults());
                    headers.referrerPolicy(referrer ->
                            referrer.policy(ReferrerPolicyHeaderWriter.ReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN)
                    );

                    headers.cacheControl(Customizer.withDefaults());

                    if (isProductionEnvironment()) {
                        headers.httpStrictTransportSecurity(hsts ->
                                hsts.maxAgeInSeconds(0).includeSubDomains(false)
                        );
                    } else {
                        headers.httpStrictTransportSecurity(hsts ->
                                hsts.maxAgeInSeconds(Duration.ofDays(365).toSeconds())
                                        .includeSubDomains(true)
                                        .preload(true)
                        );
                    }
                })
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .logout(AbstractHttpConfigurer::disable)
                .build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        final CorsConfiguration configuration = new CorsConfiguration();

        if (isProductionEnvironment()) {
            final String allowedOrigins = applicationProperties.getSecurity().getCors().getAllowedOrigins();
            configuration.setAllowedOrigins(Arrays.asList(allowedOrigins.split(",")));
        } else {
            configuration.setAllowedOrigins(Arrays.asList(
                    "http://localhost:8080",
                    "http://127.0.0.1:8080"
            ));
        }

        final String allowedMethods = applicationProperties.getSecurity().getCors().getAllowedMethods();
        configuration.setAllowedMethods(Arrays.asList(allowedMethods.split(",")));
        configuration.setAllowedHeaders(List.of("*"));
        configuration.setAllowCredentials(applicationProperties.getSecurity().getCors().isAllowCredentials());

        configuration.setExposedHeaders(Arrays.asList(
                "Access-Control-Allow-Origin",
                "Access-Control-Allow-Credentials"
        ));

        final UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12);
    }

    @Bean
    public HttpSessionEventPublisher httpSessionEventPublisher() {
        return new HttpSessionEventPublisher();
    }

    private boolean isProductionEnvironment() {
        final String renderService = environment.getProperty("RENDER_SERVICE_ID");
        final String isRender = environment.getProperty("IS_RENDER");
        final String activeProfile = environment.getProperty("spring.profiles.active");

        return renderService != null ||
                "true".equals(isRender) ||
                "prod".equals(activeProfile) ||
                "production".equals(activeProfile);
    }
}