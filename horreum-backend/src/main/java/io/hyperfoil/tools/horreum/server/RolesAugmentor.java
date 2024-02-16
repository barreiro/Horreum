package io.hyperfoil.tools.horreum.server;

import io.hyperfoil.tools.horreum.entity.user.TeamMembership;
import io.hyperfoil.tools.horreum.entity.user.UserInfo;
import io.hyperfoil.tools.horreum.entity.user.UserRole;
import io.hyperfoil.tools.horreum.svc.ServiceException;
import io.quarkus.arc.properties.IfBuildProperty;
import io.quarkus.security.identity.AuthenticationRequestContext;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.identity.SecurityIdentityAugmentor;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;
import io.smallrye.mutiny.Uni;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

@ApplicationScoped
@IfBuildProperty(name = "horreum.roles.provider", stringValue = "database")
public class RolesAugmentor implements SecurityIdentityAugmentor {

    @Inject RoleManager roleManager;

    @Override public Uni<SecurityIdentity> augment(SecurityIdentity identity, AuthenticationRequestContext context) {
        return identity.isAnonymous() ? Uni.createFrom().item(identity) : context.runBlocking(() -> rolesOverride(identity));
    }

    private SecurityIdentity rolesOverride(SecurityIdentity identity) {
        QuarkusSecurityIdentity.Builder builder = QuarkusSecurityIdentity.builder();
        builder.setAnonymous(false);
        builder.setPrincipal(identity.getPrincipal());
        builder.addAttributes(identity.getAttributes());
        builder.addCredentials(identity.getCredentials());
        builder.addPermissionChecker(identity::checkPermission);

        String username = identity.getPrincipal().getName();
        String previousRoles = roleManager.setRoles(username);
        try {
            UserInfo user = UserInfo.findById(username);

            if (user == null) {
                throw ServiceException.serverError("Unable to fetch user entity");
            }

            user.roles.stream().map(UserRole::toString).map(String::toLowerCase).forEach(builder::addRole);
            user.teams.stream().map(TeamMembership::asRole).forEach(builder::addRole);
            user.teams.stream().map(TeamMembership::asTeam).forEach(builder::addRole);
            user.teams.stream().map(TeamMembership::asUIRole).distinct().forEach(builder::addRole);

            return builder.build();
        } finally {
            roleManager.setRoles(previousRoles);
        }
    }
}
