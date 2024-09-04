package io.hyperfoil.tools.horreum.server;

import io.hyperfoil.tools.horreum.entity.user.AuthenticationToken;
import io.quarkus.security.identity.AuthenticationRequestContext;
import io.quarkus.security.identity.IdentityProvider;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.runtime.QuarkusPrincipal;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;
import io.smallrye.mutiny.Uni;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.transaction.Transactional;

/**
 * Retrieve and validate the token get from {@link AuthenticationTokenMechanism} and create a SecurityIdentity from it.
 */
@ApplicationScoped public class AuthenticationTokenIdentityProvider implements IdentityProvider<AuthenticationTokenRequest> {

    @Override public Class<AuthenticationTokenRequest> getRequestType() {
        return AuthenticationTokenRequest.class;
    }

    @Transactional
    @Override public Uni<SecurityIdentity> authenticate(AuthenticationTokenRequest request, AuthenticationRequestContext context) {
        return context.runBlocking(() -> AuthenticationToken.findValid(request.getToken()).map(AuthenticationTokenIdentityProvider::from).orElse(null));
    }

    private static SecurityIdentity from(AuthenticationToken token) {
        // roles will be populated in RolesAugmentor
        return QuarkusSecurityIdentity.builder().setPrincipal(new QuarkusPrincipal(token.user.username)).build();
    }

}
