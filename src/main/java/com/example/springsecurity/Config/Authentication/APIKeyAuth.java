package com.example.springsecurity.Config.Authentication;

import lombok.Getter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import java.util.Collection;

/*
    只负责携带认证数据
 */

@Getter
public class APIKeyAuth implements Authentication {

    private final String APIKEY;
    private boolean ifAuthenticated;

    public APIKeyAuth(boolean ifAuthenticated, String apikey) {
        this.ifAuthenticated = ifAuthenticated;
        this.APIKEY = apikey;
    }

    @Override
    public boolean isAuthenticated() {
        return this.ifAuthenticated;
    }

    @Override
    public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
        this.ifAuthenticated = isAuthenticated;
    }

    /*
        返回当前用户的权限（角色）
        可以将 API key 用户分配到某个角色（如 ROLE_USER、ROLE_ADMIN）并返回相应的权限
     */
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return null;
    }

    /*
        返回用户的凭证。凭证通常是密码、令牌或 API key，它是系统用来验证用户身份的信息
     */
    @Override
    public Object getCredentials() {
        return this.APIKEY;
    }

    /*
        返回与当前身份验证相关的附加信息。这通常包括有关用户的额外信息，如请求来源、IP 地址等
     */
    @Override
    public Object getDetails() {
        return null;
    }

    /*
        返回代表经过认证的主体（通常是用户名、用户对象、API key）的信息。principal 是代表用户的对象
     */
    @Override
    public Object getPrincipal() {
        return null;
    }

    /*
        返回当前认证对象的名称，通常是用户名。在 API key 的情况下，API key 也可以作为名称，因为它是唯一标识客户端或用户的标识符
     */
    @Override
    public String getName() {
        return this.APIKEY;
    }
}
