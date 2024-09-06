package io.hyperfoil.tools.horreum.server;

import io.hyperfoil.tools.horreum.entity.user.UserApiKey;
import io.hyperfoil.tools.horreum.svc.TimeService;
import io.quarkus.security.identity.AuthenticationRequestContext;
import io.quarkus.security.identity.IdentityProvider;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.runtime.QuarkusPrincipal;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;
import io.smallrye.mutiny.Uni;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.transaction.Transactional;

/**
 * Retrieve and validate the key got from {@link ApiKeyAuthenticationMechanism} and create a SecurityIdentity from it.
 */
@ApplicationScoped public class ApiKeyIdentityProvider implements IdentityProvider<ApiKeyAuthenticationMechanism.Request> {

    @Inject TimeService timeService;

    @Override public Class<ApiKeyAuthenticationMechanism.Request> getRequestType() {
        return ApiKeyAuthenticationMechanism.Request.class;
    }

    @Transactional
    @Override public Uni<SecurityIdentity> authenticate(ApiKeyAuthenticationMechanism.Request request, AuthenticationRequestContext context) {
        return context.runBlocking(() -> UserApiKey.findOptional(request.getKey()).filter(k -> !k.revoked).map(this::identityFromKey).orElse(null));
    }

    private SecurityIdentity identityFromKey(UserApiKey key) {
        key.access = timeService.today();

        // roles will be populated in RolesAugmentor
        return QuarkusSecurityIdentity.builder().setPrincipal(new QuarkusPrincipal(key.user.username)).build();
    }

}
