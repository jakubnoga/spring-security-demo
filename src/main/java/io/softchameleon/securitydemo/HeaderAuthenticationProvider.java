package io.softchameleon.securitydemo;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

import java.util.Objects;


public class HeaderAuthenticationProvider implements AuthenticationProvider {
    private static Logger LOGGER = LoggerFactory.getLogger(HeaderAuthenticationProvider.class);

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        var headerAuthentication = (HeaderAuthenticationToken) authentication;
        String username;

        try {
            username = Objects.requireNonNull(headerAuthentication.getName());
        } catch (NullPointerException npe) {
            throw new AuthenticationCredentialsNotFoundException("principal not found");
        }

        if (username.isEmpty()) {
            throw new AuthenticationCredentialsNotFoundException("principal not found");
        }

        return HeaderAuthenticationToken.authenticated(headerAuthentication);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return HeaderAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
