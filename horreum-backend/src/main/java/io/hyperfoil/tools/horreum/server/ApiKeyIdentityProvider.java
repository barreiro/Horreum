package io.hyperfoil.tools.horreum.server;

import io.hyperfoil.tools.horreum.entity.user.ApiKey;
import io.quarkus.security.identity.AuthenticationRequestContext;
import io.quarkus.security.identity.IdentityProvider;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.runtime.QuarkusPrincipal;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;
import io.smallrye.mutiny.Uni;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.transaction.Transactional;

/**
 * Retrieve and validate the key got from {@link ApiKeyAuthenticationMechanism} and create a SecurityIdentity from it.
 */
@ApplicationScoped public class ApiKeyIdentityProvider implements IdentityProvider<ApiKeyAuthenticationMechanism.Request> {

    @Override public Class<ApiKeyAuthenticationMechanism.Request> getRequestType() {
        return ApiKeyAuthenticationMechanism.Request.class;
    }

    @Transactional
    @Override public Uni<SecurityIdentity> authenticate(ApiKeyAuthenticationMechanism.Request request, AuthenticationRequestContext context) {
        return context.runBlocking(() -> ApiKey.findValid(request.getKey()).map(ApiKeyIdentityProvider::from).orElse(null));
    }

    private static SecurityIdentity from(ApiKey token) {
        // roles will be populated in RolesAugmentor
        return QuarkusSecurityIdentity.builder().setPrincipal(new QuarkusPrincipal(token.user.username)).build();
    }

}
