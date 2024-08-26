package io.hyperfoil.tools.horreum.server;

import io.quarkus.security.identity.request.AuthenticationRequest;
import io.quarkus.security.identity.request.BaseAuthenticationRequest;

public class AuthenticationTokenRequest extends BaseAuthenticationRequest implements AuthenticationRequest {

    private final String token;

    public AuthenticationTokenRequest(String token) {
        this.token = token;
    }

    public String getToken() {
        return token;
    }
}
