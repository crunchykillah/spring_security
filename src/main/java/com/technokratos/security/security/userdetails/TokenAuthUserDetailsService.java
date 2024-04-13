package com.technokratos.security.security.userdetails;

import com.technokratos.security.dto.AccountResponse;
import com.technokratos.security.security.exception.AuthenticationHeaderException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Slf4j
@RequiredArgsConstructor
@Service
public class TokenAuthUserDetailsService implements AuthenticationUserDetailsService<PreAuthenticatedAuthenticationToken> {

    @Override
    public UserDetails loadUserDetails(PreAuthenticatedAuthenticationToken preAuthenticatedAuthenticationToken) {
        return loadUserDetails((AccountResponse) preAuthenticatedAuthenticationToken.getPrincipal(), String.valueOf(preAuthenticatedAuthenticationToken.getCredentials()));
    }

    private UserDetails loadUserDetails(AccountResponse accountResponse, String token) {
        try {
            return Optional.ofNullable(accountResponse)
                    .map(account -> {
                        List<SimpleGrantedAuthority> authorities = List.of(new SimpleGrantedAuthority(account.role().name()));
                        return UserProfile.builder()
                                .id(account.id())
                                .username(account.login())
                                .name(account.name())
                                .authorities(authorities)
                                .isAccountNonExpired(account.isAccountNonExpired())
                                .isCredentialsNonExpired(true)
                                .isAccountNonLocked(account.isAccountNonLocked())
                                .isEnabled(true)
                                .build();
                    })
                    .orElseThrow(() -> new UsernameNotFoundException("Unknown user by token %s".formatted(token)));
        } catch (Exception exception) {
            throw new AuthenticationHeaderException(exception.getMessage());
        }
    }
}