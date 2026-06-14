package com.swift.apidev.preval.interceptor;

import java.io.IOException;
import java.util.Objects;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpRequest;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.lang.NonNull;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.stereotype.Component;

@Component
public class AuthorizationInterceptor implements ClientHttpRequestInterceptor {

    private static final String BEARER_WITH_SPACE = "Bearer ";
    private static final Logger log = LoggerFactory.getLogger(AuthorizationInterceptor.class);

    final OAuth2AuthorizedClientManager clientManager;

    AuthorizationInterceptor(OAuth2AuthorizedClientManager clientManager) {
        this.clientManager = clientManager;
    }

    @Override
    public @NonNull ClientHttpResponse intercept(@NonNull HttpRequest request, @NonNull byte[] body, @NonNull ClientHttpRequestExecution execution)
            throws IOException {
        // Attempt to authorize or re-authorize (if required)
        var authorizeRequest = OAuth2AuthorizeRequest.withClientRegistrationId("swift")
                .principal("swift")
                .build();

        // Retrieve the access token or reuse the existing one
        var authorizedClient = clientManager.authorize(authorizeRequest);
        Objects.requireNonNull(authorizedClient, "Client credentials failed, client is null");

        final String token = authorizedClient.getAccessToken().getTokenValue();
        
        // Log the obtained access token for debugging purposes
        log.info("Access token obtained: {}", token); 
    

        // Set the Bearer token in 'Authorization' header
        request.getHeaders().add(HttpHeaders.AUTHORIZATION, BEARER_WITH_SPACE.concat(token));

        return execution.execute(request, body);
    }
}
