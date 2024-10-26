package com.example.springsecurity.Config.Filters;

import com.example.springsecurity.Config.Authentication.APIKeyAuth;
import com.example.springsecurity.Config.AuthenticationManagers.APIKeyAuthManager;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/*
    过滤器是用来处理进入应用的请求，实施安全检查的组件
    过滤器主要负责：

    1. 请求拦截：在请求达到目标（如控制器）之前，过滤器会检查并处理请求。这可能包括验证身份、检查权限、记录日志等。

    2. 认证和授权：过滤器可以拦截请求并执行认证（确定请求者是谁）和授权（确定请求者是否有权限执行请求的操作）。

    3. 请求修改：在某些情况下，过滤器可以修改进入的请求（例如，添加、修改请求头）或响应，以满足特定的安全需求。

    4. 安全逻辑实施：过滤器按照定义的安全策略实施安全控制，如防止跨站请求伪造（CSRF），提供跨域资源共享（CORS）支持等。
 */
public class APIKeyFilter extends OncePerRequestFilter {

    private final APIKeyAuthManager apiKeyAuthManager;

    public APIKeyFilter(APIKeyAuthManager apiKeyAuthManager) {
        this.apiKeyAuthManager = apiKeyAuthManager;
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {

        /*
            这里执行一个双filter，如果没有提供API Key，那么就去 default 的 Basic auth 去检查
        */

        /*
            1. 创建为认证的authentication object，委托给 authentication manager取认证
            2. 然后从 manager那里拿回这个 authentication，如果被认证成功了，
            3. 那么将request发送给下一个filter
         */

        // 1.
        String apikey = request.getHeader("x-api-key");
        System.out.println(apikey);

        // 如果未提供
        if (apikey == null || apikey.isEmpty()) {
            filterChain.doFilter(request, response);
            // 必须加，否则会报错，因为在执行完后续的filter之后会返回到这里继续执行下面的代码，但这个时候我们的 apikey 是 null
            return;
        }

        /*
             用于存储当前线程的安全上下文（即当前用户的安全详细信息）。
             这里使用 getContext() 方法获取当前的 SecurityContext，然后使用 setAuthentication(...)
             方法将我们的自定义 Authentication 设置到上下文中。
             这样，后续的 Spring Security 过滤器和其他部分的代码就可以通过 SecurityContextHolder 访问到当前认证的用户信息
        */

        // 创建一个没有被验证的
        APIKeyAuth apiKeyAuth = new APIKeyAuth(false, apikey);
        Authentication authenticate = apiKeyAuthManager.authenticate(apiKeyAuth);
        if(authenticate.isAuthenticated()){
            SecurityContextHolder.getContext().setAuthentication(authenticate);
            /*
                当前过滤器已完成其任务，并且请求应继续传递到下一个过滤器或最终的目的地（如控制器）。
                如果不调用这个方法，请求处理流程将在当前过滤器停止，后续的过滤器和请求处理逻辑不会得到执行
             */
            filterChain.doFilter(request, response);
        }else{
            throw new BadCredentialsException("Ah ohh");
        }

//        try {
//            // 2.
//            Authentication authRequest = new APIKeyAuth(false, apikey);
//            Authentication authResult = apiKeyAuthManager.authenticate(authRequest);
//            // 3.
//            if (authResult.isAuthenticated()) {

//                SecurityContextHolder.getContext().setAuthentication(authResult);

//                filterChain.doFilter(request, response);
//            } else {
//                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
//            }
//        } catch (AuthenticationException e) {
//            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
//        }
    }
}
