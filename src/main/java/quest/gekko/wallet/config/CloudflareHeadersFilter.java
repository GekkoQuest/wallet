package quest.gekko.wallet.config;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
@Slf4j
public class CloudflareHeadersFilter implements Filter {

    @Override
    public void doFilter(final ServletRequest request, final ServletResponse response, final FilterChain chain) throws IOException, ServletException {
        if (request instanceof HttpServletRequest httpRequest) {
            final HttpServletRequest wrappedRequest = new CloudflareHttpServletRequestWrapper(httpRequest);
            chain.doFilter(wrappedRequest, response);
        } else {
            chain.doFilter(request, response);
        }
    }

    private static class CloudflareHttpServletRequestWrapper extends HttpServletRequestWrapper {
        private final Map<String, String> customHeaders;

        public CloudflareHttpServletRequestWrapper(final HttpServletRequest request) {
            super(request);
            this.customHeaders = new HashMap<>();

            final String cfConnectingIp = request.getHeader("CF-Connecting-IP");
            final String xForwardedFor = request.getHeader("X-Forwarded-For");
            // String xRealIp = request.getHeader("X-Real-IP");

            if (cfConnectingIp != null && !cfConnectingIp.isEmpty()) {
                customHeaders.put("X-Forwarded-For", cfConnectingIp);
                customHeaders.put("X-Real-IP", cfConnectingIp);
            } else if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
                final String realIp = xForwardedFor.split(",")[0].trim();
                customHeaders.put("X-Real-IP", realIp);
            }

            final String cfVisitorProtocol = request.getHeader("CF-Visitor");
            final String xForwardedProto = request.getHeader("X-Forwarded-Proto");

            if (cfVisitorProtocol != null && cfVisitorProtocol.contains("https")) {
                customHeaders.put("X-Forwarded-Proto", "https");
            } else if (xForwardedProto != null) {
                customHeaders.put("X-Forwarded-Proto", xForwardedProto);
            }
        }

        @Override
        public String getHeader(final String name) {
            final String customHeader = customHeaders.get(name);
            return customHeader != null ? customHeader : super.getHeader(name);
        }

        @Override
        public Enumeration<String> getHeaders(final String name) {
            final String customHeader = customHeaders.get(name);

            if (customHeader != null) {
                return Collections.enumeration(Collections.singletonList(customHeader));
            }

            return super.getHeaders(name);
        }

        @Override
        public Enumeration<String> getHeaderNames() {
            return Collections.enumeration(customHeaders.keySet());
        }
    }
}