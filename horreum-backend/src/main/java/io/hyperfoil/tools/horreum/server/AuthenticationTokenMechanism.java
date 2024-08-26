package io.hyperfoil.tools.horreum.server;

import io.netty.handler.codec.http.HttpResponseStatus;
import io.quarkus.logging.Log;
import io.quarkus.security.identity.IdentityProviderManager;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.identity.request.AuthenticationRequest;
import io.quarkus.vertx.http.runtime.security.ChallengeData;
import io.quarkus.vertx.http.runtime.security.HttpAuthenticationMechanism;
import io.quarkus.vertx.http.runtime.security.HttpCredentialTransport;
import io.smallrye.mutiny.Uni;
import io.vertx.ext.web.RoutingContext;
import jakarta.enterprise.context.ApplicationScoped;

import java.util.Collections;
import java.util.Optional;
import java.util.Set;

/**
 * Look for a special HTTP header to provide authentication of HTTP requests
 */
@ApplicationScoped public class AuthenticationTokenMechanism implements HttpAuthenticationMechanism {

    public static final String HORREUM_AUTHENTICATION_TOKEN_HEADER = "X-Horreum-Authentication-Token";

    @Override public Uni<SecurityIdentity> authenticate(RoutingContext context, IdentityProviderManager identityProviderManager) {
        String headerValue = context.request().headers().get(HORREUM_AUTHENTICATION_TOKEN_HEADER);
        return headerValue == null ? Uni.createFrom().nullItem() : identityProviderManager.authenticate(new AuthenticationTokenRequest(headerValue));
    }

    @Override public Uni<ChallengeData> getChallenge(RoutingContext context) {
        return Uni.createFrom().item(new ChallengeData(HttpResponseStatus.UNAUTHORIZED.code(), null, null));
    }
    
    @Override public Set<Class<? extends AuthenticationRequest>> getCredentialTypes() {
        return Collections.singleton(AuthenticationTokenRequest.class);
    }

    @Override public Uni<HttpCredentialTransport> getCredentialTransport(RoutingContext context) {
        return Uni.createFrom().item(new HttpCredentialTransport(HttpCredentialTransport.Type.OTHER_HEADER, HORREUM_AUTHENTICATION_TOKEN_HEADER));
    }
}
