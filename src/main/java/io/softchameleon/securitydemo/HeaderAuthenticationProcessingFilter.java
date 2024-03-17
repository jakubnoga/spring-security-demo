package io.softchameleon.securitydemo;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.Getter;
import lombok.Setter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.core.log.LogMessage;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.servlet.HandlerExceptionResolver;

import java.io.IOException;

@Component
public class HeaderAuthenticationProcessingFilter extends OncePerRequestFilter {
    private final String X_ANT_USERROLES = "x-ant-userroles";
    private final String X_ANT_USER = "x-ant-user";

    @Getter
    @Setter
    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    @Qualifier("handlerExceptionResolver")
    private HandlerExceptionResolver resolver;
    private SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder
            .getContextHolderStrategy();

    private SecurityContextRepository securityContextRepository = new RequestAttributeSecurityContextRepository();

    private static Logger LOGGER = LoggerFactory.getLogger(HeaderAuthenticationProcessingFilter.class);

    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {
        var userRolesHeader = request.getHeader(X_ANT_USERROLES);
        var userHeader = request.getHeader(X_ANT_USER);

        logger.info(userHeader);
        logger.info(userRolesHeader);
        return getAuthenticationManager().authenticate(HeaderAuthenticationToken.unauthenticated(userHeader, userRolesHeader));
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        try {
            var authResult = attemptAuthentication(request, response);
            SecurityContext context = this.securityContextHolderStrategy.createEmptyContext();
            context.setAuthentication(authResult);
            this.securityContextHolderStrategy.setContext(context);
            this.securityContextRepository.saveContext(context, request, response);
            if (this.logger.isDebugEnabled()) {
                this.logger.debug(LogMessage.format("Set SecurityContextHolder to %s", authResult));
            }
        } catch (AuthenticationException ae) {
            this.logger.error(LogMessage.format("Failed to authenticate %s", ae.getMessage()));
            resolver.resolveException(request, response, null, ae);
            this.securityContextHolderStrategy.clearContext();
        }

        filterChain.doFilter(request, response);
    }
}
