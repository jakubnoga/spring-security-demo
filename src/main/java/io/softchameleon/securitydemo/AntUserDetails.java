package io.softchameleon.securitydemo;

import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Arrays;
import java.util.Collection;

public class AntUserDetails implements UserDetails {
    @Getter
    private final Collection<? extends GrantedAuthority> authorities;

    @Getter
    private final String username;

    public AntUserDetails(String username, Collection<? extends GrantedAuthority> roles) {
        super();
        this.username = username;
        this.authorities = roles;
    }

    @Override
    public String getPassword() {
        return null;
    }


    @Override
    public boolean isAccountNonExpired() {
        return false;
    }

    @Override
    public boolean isAccountNonLocked() {
        return false;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return false;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
