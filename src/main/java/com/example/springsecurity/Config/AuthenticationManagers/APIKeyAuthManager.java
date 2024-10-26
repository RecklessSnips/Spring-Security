package com.example.springsecurity.Config.AuthenticationManagers;

import com.example.springsecurity.Config.IdpProviders.APIKeyProvider;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

/*
    负责协调认证流程
 */
public class APIKeyAuthManager implements AuthenticationManager {

    private final String key;

    public APIKeyAuthManager(String key) {
        this.key = key;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        // Instantiate Idp
        APIKeyProvider provider = new APIKeyProvider(key);
        // 如果支持（防止有多个filter搞混）
        if (provider.supports(authentication.getClass())){

            return provider.authenticate(authentication);
        }
        // 未被验证的
        throw new RuntimeException("Unmatched authentication type with Identity provider");
    }
}
