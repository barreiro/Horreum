package io.hyperfoil.tools.horreum.svc;

import io.hyperfoil.tools.horreum.api.internal.services.UserService;
import io.hyperfoil.tools.horreum.entity.user.UserApiKey;
import io.hyperfoil.tools.horreum.entity.user.UserInfo;
import io.hyperfoil.tools.horreum.server.WithRoles;
import io.hyperfoil.tools.horreum.svc.user.UserBackEnd;
import io.quarkus.logging.Log;
import io.quarkus.scheduler.Scheduled;
import io.quarkus.security.Authenticated;
import io.quarkus.security.identity.SecurityIdentity;
import jakarta.annotation.security.PermitAll;
import jakarta.annotation.security.RolesAllowed;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Instance;
import jakarta.inject.Inject;
import jakarta.transaction.Transactional;

import java.security.SecureRandom;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

import static java.text.MessageFormat.format;
import static java.util.Collections.emptyList;

@Authenticated
@ApplicationScoped
public class UserServiceImpl implements UserService {

    /**
     * default number of days API keys remain active after key usage
     */
    public static final long DEFAULT_API_KEY_ACTIVE_DAYS = 30;

    private static final int RANDOM_PASSWORD_LENGTH = 15;

    @Inject SecurityIdentity identity;

    @Inject Instance<UserBackEnd> backend;

    @Inject TimeService timeService;

    @Inject NotificationServiceImpl notificationServiceimpl;

    private UserInfo currentUser() {
        return UserInfo.<UserInfo>findByIdOptional(getUsername()).orElseThrow(() -> ServiceException.notFound(format("Username {0} not found", getUsername())));
    }

    private String getUsername() {
        return identity.getPrincipal().getName();
    }

    @Override public List<String> getRoles() {
        return identity.getRoles().stream().toList();
    }

    @RolesAllowed({ Roles.MANAGER, Roles.ADMIN })
    @Override public List<UserData> searchUsers(String query) {
        return backend.get().searchUsers(query);
    }

    @RolesAllowed({ Roles.MANAGER, Roles.ADMIN })
    @Override public List<UserData> info(List<String> usernames) {
        return backend.get().info(usernames);
    }

    // ideally we want to enforce these roles in some endpoints, but for now this has to be done in the code
    // @RolesAllowed({ Roles.ADMIN, Roles.MANAGER })
    @Override public void createUser(NewUser user) {
        validateNewUser(user);
        userIsManagerForTeam(user.team);
        backend.get().createUser(user);
        createLocalUser(user.user.username, user.team, user.roles != null && user.roles.contains(Roles.MACHINE) ? user.password : null);
        Log.infov("{0} created user {1} {2} with username {3} on team {4}", identity.getPrincipal().getName(), user.user.firstName, user.user.lastName, user.user.username, user.team);
    }

    @RolesAllowed({ Roles.ADMIN, Roles.MANAGER })
    @Override public void removeUser(String username) {
        if (identity.getPrincipal().getName().equals(username)) {
            throw ServiceException.badRequest("Cannot remove yourself");
        }
        backend.get().removeUser(username);
        removeLocalUser(username);
        Log.infov("{0} removed user {1}", getUsername(), username);
    }

    @Override public List<String> getTeams() {
        return backend.get().getTeams();
    }

    @Transactional
    @WithRoles(extras = Roles.HORREUM_SYSTEM)
    @Override public String defaultTeam() {
        UserInfo userInfo = currentUser();
        return userInfo.defaultTeam != null ? userInfo.defaultTeam : "";
    }

    @Transactional
    @WithRoles(addUsername = true)
    @Override public void setDefaultTeam(String unsafeTeam) {
        UserInfo userInfo = currentUser();
        userInfo.defaultTeam = validateTeamName(unsafeTeam);
        userInfo.persistAndFlush();
    }

    // @RolesAllowed({ Roles.ADMIN, Roles.MANAGER })
    @Override public Map<String, List<String>> teamMembers(String unsafeTeam) {
        String team = validateTeamName(unsafeTeam);
        userIsManagerForTeam(team);

        Map<String, List<String>> teamMembers = backend.get().teamMembers(team);
        safeMachineAccounts(team).forEach(teamMembers::remove); // exclude machine accounts
        return teamMembers;
    }

    // @RolesAllowed({ Roles.ADMIN, Roles.MANAGER })
    @Override public void updateTeamMembers(String unsafeTeam, Map<String, List<String>> newRoles) {
        String team = validateTeamName(unsafeTeam);
        userIsManagerForTeam(team);

        // add existing users missing from the new roles map to get their roles removed
        Map<String, List<String>> roles = new HashMap<>(newRoles);
        backend.get().teamMembers(team).forEach((username, old) -> roles.putIfAbsent(username, emptyList()));
        safeMachineAccounts(team).forEach(roles::remove); // exclude machine accounts

        backend.get().updateTeamMembers(team, roles);
    }

    @RolesAllowed(Roles.ADMIN)
    @Override public List<String> getAllTeams() {
        return backend.get().getAllTeams();
    }

    @RolesAllowed(Roles.ADMIN)
    @Override public void addTeam(String unsafeTeam) {
        String team = validateTeamName(unsafeTeam);
        backend.get().addTeam(team);
        Log.infov("{0} created team {1}", getUsername(), team);
    }

    @RolesAllowed(Roles.ADMIN)
    @Override public void deleteTeam(String unsafeTeam) {
        String team = validateTeamName(unsafeTeam);
        backend.get().deleteTeam(team);
        Log.infov("{0} deleted team {1}", getUsername(), team);
    }

    @RolesAllowed(Roles.ADMIN)
    @Override public List<UserData> administrators() {
        return backend.get().administrators();
    }

    @RolesAllowed(Roles.ADMIN)
    @Override public void updateAdministrators(List<String> newAdmins) {
        if (!newAdmins.contains(identity.getPrincipal().getName())) {
            throw ServiceException.badRequest("Cannot remove yourself from administrator list");
        }
        backend.get().updateAdministrators(newAdmins);
    }

    // @RolesAllowed({Roles.ADMIN, Roles.MANAGER})
    @Override public List<UserData> machineAccounts(String unsafeTeam) {
        String team = validateTeamName(unsafeTeam);
        userIsManagerForTeam(team);
        return backend.get().machineAccounts(team);
    }

    // @RolesAllowed({ Roles.ADMIN, Roles.MANAGER })
    @Transactional
    @WithRoles(fromParams = SecondParameter.class)
    @Override public String resetPassword(String unsafeTeam, String username) {
        // reset the password for machine accounts of a specified team
        // those passwords are always stored in the database, whatever is the backend

        String team = validateTeamName(unsafeTeam);
        userIsManagerForTeam(team);
        if (backend.get().machineAccounts(team).stream().noneMatch(data -> data.username.equals(username))) {
            throw ServiceException.badRequest(format("User {0} is not machine account of team {1}", username, team));
        }
        String newPassword = new SecureRandom().ints(RANDOM_PASSWORD_LENGTH, '0', 'z' + 1).collect(StringBuilder::new, StringBuilder::appendCodePoint, StringBuilder::append).toString();
        UserInfo.<UserInfo>findByIdOptional(username).orElseThrow(() -> ServiceException.notFound(format("Username {0} not found", username))).setPassword(newPassword);
        Log.infov("{0} reset password of user {1}", getUsername(), username);
        return newPassword;
    }

    private void userIsManagerForTeam(String team) {
        if (!identity.getRoles().contains(Roles.ADMIN) && !identity.hasRole(team.substring(0, team.length() - 4) + Roles.MANAGER)) {
            throw ServiceException.badRequest(format("This user is not a manager for team {0}", team));
        }
    }

    private static void validateNewUser(NewUser user) {
        if (user == null) {
            throw ServiceException.badRequest("Missing user as the request body");
        } else if (user.user == null || user.user.username == null) {
            throw ServiceException.badRequest("Missing new user info");
        } else if (user.user.username.startsWith("horreum.")) {
            throw ServiceException.badRequest("User names starting with 'horreum.' are reserved for internal use");
        }
        if (user.team != null) {
            user.team = validateTeamName(user.team);
        } else if (user.roles != null && user.roles.contains(Roles.MACHINE)) {
            throw ServiceException.badRequest("Machine account must have a team");
        }
    }

    private static String validateTeamName(String unsafeTeam) {
        String team = Util.destringify(unsafeTeam);
        if (team == null || team.isBlank()) {
            throw ServiceException.badRequest("No team name!!!");
        } else if (team.startsWith("horreum.")) {
            throw ServiceException.badRequest("Team names starting with 'horreum.' are reserved for internal use");
        } else if (!team.endsWith("-team")) {
            throw ServiceException.badRequest("Team name must end with '-team' suffix");
        } else if (team.length() > 64) {
            throw ServiceException.badRequest("Team name too long. Please think on a shorter team name!!!");
        }
        return team;
    }

    private List<String> safeMachineAccounts(String team) {
        try {
            return backend.get().machineAccounts(team).stream().map(data -> data.username).toList();
        } catch (Exception e) {
            // ignore exception as the team may not exist
            return List.of();
        }
    }

    /**
     * The user info that is always local, no matter what is the backend
     */
    @Transactional
    @WithRoles(fromParams = FirstParameter.class)
    void createLocalUser(String username, String defaultTeam, String password) {
        UserInfo userInfo = UserInfo.<UserInfo>findByIdOptional(username).orElse(new UserInfo(username));
        if (defaultTeam != null) {
            userInfo.defaultTeam = defaultTeam;
            if (password != null) {
                userInfo.setPassword(password);
            }
            userInfo.persist();
        }
    }

    @Transactional
    @WithRoles(fromParams = FirstParameter.class)
    void removeLocalUser(String username) {
        try {
            UserInfo.deleteById(username);
        } catch (Exception e) {
            // ignore
        }
    }

    // --- //

    @Transactional
    @WithRoles(addUsername = true)
    @Override public String newApiKey(ApiKeyRequest request) {
        validateApiKeyName(request.name == null ? "" : request.name);
        UserInfo userInfo = currentUser();

        UserApiKey newKey = new UserApiKey(request, timeService.today(), DEFAULT_API_KEY_ACTIVE_DAYS);
        newKey.user = userInfo;
        userInfo.apiKeys.add(newKey);
        newKey.persist();
        userInfo.persist();

        Log.infov("{0} created API key \"{1}\"", getUsername(), request.name == null ? "" : request.name);
        return newKey.keyString();
    }

    @Transactional
    @WithRoles(extras = Roles.HORREUM_SYSTEM)
    @Override public List<ApiKeyResponse> apiKeys() {
        return currentUser().apiKeys.stream()
                                    .filter(t -> !t.isArchived(timeService.today()))
                                    .sorted()
                                    .map(UserApiKey::toResponse)
                                    .toList();
    }

    @Transactional
    @WithRoles(addUsername = true)
    @Override public void renameApiKey(long keyId, String newName) {
        validateApiKeyName(newName == null ? "" : newName);
        UserApiKey key = UserApiKey.<UserApiKey>findByIdOptional(keyId).orElseThrow(() -> ServiceException.notFound(format("Key with id {0} not found", keyId)));
        if (key.revoked) {
            throw ServiceException.badRequest("Can't rename revoked key");
        }
        String oldName = key.name;
        key.name = newName == null ? "" : newName;
        Log.infov("{0} renamed API key \"{1}\" to \"{2}\"", getUsername(), oldName, newName == null ? "" : newName);
    }

    @Transactional
    @WithRoles(addUsername = true)
    @Override public void revokeApiKey(long keyId) {
        UserApiKey key = UserApiKey.<UserApiKey>findByIdOptional(keyId).orElseThrow(() -> ServiceException.notFound(format("Key with id {0} not found", keyId)));
        key.revoked = true;
        Log.infov("{0} revoked API key \"{1}\"", getUsername(), key.name);
    }

    @PermitAll
    @Transactional
    @WithRoles(extras = Roles.HORREUM_SYSTEM)
    @Scheduled(every = "P1d") // daily -- it may lag up tp 24h compared to the actual date, but keys are revoked 24h after notification
    public void apiKeyDailyTask() {
        // notifications of keys expired and about to expire -- hardcoded to send multiple notices in the week prior to expiration
        for (long toExpiration : List.of(7, 2, 1, 0, -1)) {
            UserApiKey.<UserApiKey>stream("#UserApiKey.expire", timeService.today().plusDays(toExpiration))
                      .forEach(key -> notificationServiceimpl.notifyApiKeyExpiration(key, toExpiration));
        }
        // revoke expired keys -- could be done directly in the DB but iterate instead to be able to log
        UserApiKey.<UserApiKey>stream("#UserApiKey.pastExpiration", timeService.today()).forEach(key -> {
            Log.infov("Revoked idle API key \"{0}\"", key.name);
            key.revoked = true;
        });
    }

    private void validateApiKeyName(String keyName) {
        if (keyName.startsWith("horreum.")) {
            throw ServiceException.badRequest("key names starting with 'horreum.' are reserved for internal use");
        }
    }

    // --- //

    public static final class FirstParameter implements Function<Object[], String[]> {
        @Override public String[] apply(Object[] objects) {
            return new String[] { (String) objects[0] };
        }
    }

    public static final class SecondParameter implements Function<Object[], String[]> {
        @Override public String[] apply(Object[] objects) {
            return new String[] { (String) objects[1] };
        }
    }
}
