package by.home.securitytest.security;

import org.springframework.security.core.GrantedAuthority;

public class Authority implements GrantedAuthority {

    private final String auth;

    public Authority(String auth) {
        this.auth = auth;
    }

    @Override
    public String getAuthority() {
        return this.auth;
    }
}
