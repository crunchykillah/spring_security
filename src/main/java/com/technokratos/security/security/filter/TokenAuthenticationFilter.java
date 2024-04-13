package com.technokratos.security.security.filter;

import com.technokratos.security.dto.AccountResponse;
import com.technokratos.security.dto.TokenRequest;
import com.technokratos.security.security.client.JwtTokenClient;
import com.technokratos.security.util.HttpResponseUtil;
import com.technokratos.security.util.HttpSettingUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.security.web.authentication.preauth.RequestHeaderAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Objects;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;

@Slf4j
public class TokenAuthenticationFilter extends RequestHeaderAuthenticationFilter {

    private final JwtTokenClient jwtTokenClient;

    public TokenAuthenticationFilter(JwtTokenClient jwtTokenClient, AuthenticationManager authenticationManager) {
        this.jwtTokenClient = jwtTokenClient;
        this.setAuthenticationManager(authenticationManager);
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException {
        String requestURI = ((HttpServletRequest) request).getRequestURI();

        try {
            String authorizationHeader = ((HttpServletRequest) request).getHeader(AUTHORIZATION);
            TokenRequest token = HttpSettingUtil.getTokenFromValidatedAuthorizationHeader(authorizationHeader);
            if (Objects.nonNull(token)) {
                AccountResponse accountResponse = jwtTokenClient.userInfoByToken(token);
                PreAuthenticatedAuthenticationToken preAuthToken = new PreAuthenticatedAuthenticationToken(accountResponse, token);
                SecurityContextHolder.getContext().setAuthentication(preAuthToken);
            }
            chain.doFilter(request, response);
        } catch (Exception exception) {
            HttpResponseUtil.putExceptionInResponse(((HttpServletRequest) request), ((HttpServletResponse) response),
                    exception, HttpServletResponse.SC_UNAUTHORIZED);
        }
    }
}
