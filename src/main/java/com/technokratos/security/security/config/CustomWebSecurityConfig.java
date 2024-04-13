package com.technokratos.security.security.config;

import com.technokratos.security.security.client.JwtTokenClient;
import com.technokratos.security.security.filter.TokenAuthenticationFilter;
import com.technokratos.security.security.userdetails.TokenAuthUserDetailsService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationProvider;
import org.springframework.security.web.authentication.preauth.RequestHeaderAuthenticationFilter;

import java.util.Collections;

@RequiredArgsConstructor
@EnableWebSecurity
public class CustomWebSecurityConfig extends WebSecurityConfigurerAdapter {

    private static final String[] PERMIT_ALL = {"/public", "/api/auth/signin"};

    private static final String[] IGNORE = {
    };

    private final TokenAuthUserDetailsService tokenAuthUserDetailsService;
    private final JwtTokenClient JwtTokenClient;

    @Override
    public void configure(WebSecurity web) {
        web.ignoring().antMatchers(IGNORE);
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
        http.sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .addFilterAfter(tokenAuthFilter(), RequestHeaderAuthenticationFilter.class)
                .authenticationProvider(authProvider())
                .authorizeRequests()
                .antMatchers(PERMIT_ALL).permitAll()
                .anyRequest().authenticated()
                .and()
                .cors()
                .and()
                .csrf().disable()
                .formLogin().disable()
                .httpBasic().disable()
                .logout().disable();
    }

    @Bean
    public AuthenticationProvider authProvider() {
        PreAuthenticatedAuthenticationProvider authProvider = new PreAuthenticatedAuthenticationProvider();
        authProvider.setPreAuthenticatedUserDetailsService(tokenAuthUserDetailsService);
        authProvider.setThrowExceptionWhenTokenRejected(false);

        return authProvider;
    }

    @Override
    protected AuthenticationManager authenticationManager() {
        return new ProviderManager(Collections.singletonList(authProvider()));
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
    public RequestHeaderAuthenticationFilter tokenAuthFilter() {
        return new TokenAuthenticationFilter(JwtTokenClient, authenticationManager());
    }

}
