package io.softchameleon.securitydemo;

import lombok.Getter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Arrays;
import java.util.Collection;

public class HeaderAuthenticationToken extends AbstractAuthenticationToken {
    @Getter
    private final AntUserDetails principal;

    private HeaderAuthenticationToken(String username, Collection<? extends GrantedAuthority> grantedAuthorities) {
        super(grantedAuthorities);
        this.principal = new AntUserDetails(username, grantedAuthorities);
    }

    @Override
    public Object getCredentials() {
        return null;
    }

    @Override
    public Object getPrincipal() {
        return principal;
    }

    private static HeaderAuthenticationToken getInstance(String username, String roles) {
        var rolesArray = roles != null ? roles.split(",") : new String[]{};
        var grantedAuthorities = Arrays.stream(rolesArray).map(SimpleGrantedAuthority::new).toList();
        return new HeaderAuthenticationToken(username, grantedAuthorities);
    }

    ;

    public static HeaderAuthenticationToken unauthenticated(String username, String roles) {
        var token = getInstance(username, roles);
        token.setAuthenticated(false);

        return token;
    }

    public static HeaderAuthenticationToken authenticated(HeaderAuthenticationToken token) {
        var newToken = new HeaderAuthenticationToken(((AntUserDetails) token.getPrincipal()).getUsername(), token.getAuthorities());
        newToken.setAuthenticated(true);

        return newToken;
    }
}
