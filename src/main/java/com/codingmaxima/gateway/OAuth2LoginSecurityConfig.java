package com.codingmaxima.gateway;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcReactiveOAuth2UserService;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.userinfo.ReactiveOAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;
import org.springframework.security.web.server.SecurityWebFilterChain;
import reactor.core.publisher.Mono;

import java.util.HashSet;
import java.util.Set;

import static org.springframework.security.config.Customizer.withDefaults;

@EnableWebFluxSecurity
public class OAuth2LoginSecurityConfig {

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        http
                .authorizeExchange(authorize -> authorize
                        .pathMatchers("/").permitAll()
                        .anyExchange().authenticated()
                )
                .oauth2Login(withDefaults());

        return http.build();
    }

    @Bean
    public ReactiveOAuth2UserService<OidcUserRequest, OidcUser> oidcUserService() {
        final OidcReactiveOAuth2UserService delegate = new OidcReactiveOAuth2UserService();

        return (userRequest) -> {
            // Delegate to the default implementation for loading a user
            return delegate.loadUser(userRequest)
                    .flatMap((oidcUser) -> {
                        OAuth2AccessToken accessToken = userRequest.getAccessToken();
                        Set<GrantedAuthority> mappedAuthorities = new HashSet<>();
                        // added one
                        mappedAuthorities.add(new OidcUserAuthority("ROLE_ADMIN", oidcUser.getIdToken(), oidcUser.getUserInfo()));
                        System.out.println(oidcUser.getUserInfo().getEmail());
                        System.out.println(oidcUser.getUserInfo().getGivenName());
                        System.out.println(oidcUser.getUserInfo().getFullName());
                        // TODO
                        // 1) Fetch the authority information from the protected resource using accessToken
                        // 2) Map the authority information to one or more GrantedAuthority's and add it to mappedAuthorities

                        // 3) Create a copy of oidcUser but use the mappedAuthorities instead
                        oidcUser = new DefaultOidcUser(mappedAuthorities, oidcUser.getIdToken(), oidcUser.getUserInfo());

                        return Mono.just(oidcUser);
                    });
        };
    }
}