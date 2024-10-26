package com.example.springsecurity.Config.IdpProviders;

import com.example.springsecurity.Config.Authentication.APIKeyAuth;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

/*
    负责执行具体的认证逻辑
*/
public class APIKeyProvider implements AuthenticationProvider {

    private final String APIKEY;

    public APIKeyProvider(String apikey) {
        APIKEY = apikey;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        APIKeyAuth apiKeyAuth = (APIKeyAuth) authentication;
        if (apiKeyAuth.getAPIKEY().equals(APIKEY)) {
            apiKeyAuth.setAuthenticated(true);
            return apiKeyAuth;
        }else{
            throw new BadCredentialsException("Wrong Credentials!");
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return APIKeyAuth.class.equals(authentication);
    }
}
