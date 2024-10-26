package com.example.springsecurity.Config.Security;

import com.example.springsecurity.Config.Filters.APIKeyFilter;
import com.example.springsecurity.Config.AuthenticationManagers.APIKeyAuthManager;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import static org.springframework.security.config.Customizer.withDefaults;

/*
    SecurityConfig 是配置 Spring Security 的中心地点，通常通过一个或多个 Java 配置类实现。它的关键职责包括：

    1. 安全策略定义：定义应用的安全策略，如何并在何处应用安全控制（例如，哪些URL需要认证，哪些需要特定权限）。

    2. 过滤器链配置：设置和配置过滤器链。这包括决定哪些过滤器被包括在内、它们的顺序如何，以及它们应该如何配置。

    3. 认证管理：配置认证管理器，决定使用哪些认证提供者。这里可以配置如用户名密码认证、LDAP认证、OAuth2认证等。

    4. 其他安全特性配置：例如配置 HTTPS、设置 CSRF 保护、配置会话管理策略等。

    5. 资源访问控制：定义资源（如HTTP请求路径、方法等）的访问控制策略。
 */

@Configuration
//@EnableWebMvc
//@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    @Value("${secret}")
    private String key;

    /*
        手动将这些类 instantiate，交给 ApplicationContext 管理
     */
    @Bean
    public APIKeyAuthManager apiKeyAuthManager() {
        return new APIKeyAuthManager(key);
    }

    @Bean
    public APIKeyFilter apiKeyFilter(APIKeyAuthManager apiKeyAuthManager) {
        return new APIKeyFilter(apiKeyAuthManager);
    }

    @Bean
    public UserDetailsService userDetailsService() {
        return new InMemoryUserDetailsManager(
                User.withUsername("admin")
                        .password("{noop}admin") // 必须加一个 encoder
                        .roles("USER")
                        .build()
                ,
                User.withUsername("ahsoka")
                        .password("{noop}ahsoka")
                        .roles("USER")
                        .authorities("read")
                        .build()
        );
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, APIKeyFilter apiKeyFilter) throws Exception{
        return http
                // 开启 BasicAuth，用默认设置
                .httpBasic(withDefaults())
                .addFilterBefore(apiKeyFilter, BasicAuthenticationFilter.class)
                // 新的写法，让所有的请求都需要被验证
                .authorizeHttpRequests(
                        /*
                         Filter level authorization
                            Matcher method      authorization rule
                             anyRequest()         authenticated()
                         1. 关注用哪些 matcher methods
                         2. 关注如何应用 authorization role
                         */
                        // Authorization role
                        authorize -> authorize
//                                .anyRequest()  // 暂时注释掉 matcher method
                                // Authority Roles 本质上是一样的，只不过roles加了 ROLE_ 前缀
                                // 只能授权给拥有以下权限的用户
//                                .hasAuthority("read")
                                // 任意权限
//                                .hasAnyAuthority("read", "write")
                                // 角色，任意角色
//                                .hasRole("ADMIN")
//                                .hasAnyRole("ADMIN", "MANAGER")
//                                .authenticated()

                        // Matcher method: requestMatchers(), securityMatchers()
//                                .requestMatchers("/test/*").permitAll()
                                .anyRequest()
                                .authenticated()

                )
                .build();
        /*
             UsernamePasswordAuthenticationFilter.class 是用于验证 Form, 默认只会在 /login 这样的路径下触发
             通常是 Post请求，然后传递给 AuthenticationManager 进行验证
         */
    }
}
