package io.hyperfoil.tools.horreum.svc.user;

import io.hyperfoil.tools.horreum.api.internal.services.UserService;
import io.hyperfoil.tools.horreum.entity.user.Team;
import io.hyperfoil.tools.horreum.entity.user.TeamMembership;
import io.hyperfoil.tools.horreum.entity.user.TeamRole;
import io.hyperfoil.tools.horreum.entity.user.UserInfo;
import io.hyperfoil.tools.horreum.entity.user.UserRole;
import io.hyperfoil.tools.horreum.server.WithRoles;
import io.hyperfoil.tools.horreum.svc.Roles;
import io.hyperfoil.tools.horreum.svc.ServiceException;
import io.quarkus.arc.lookup.LookupIfProperty;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.CriteriaQuery;
import jakarta.transaction.Transactional;
import org.jboss.logging.Logger;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;

import static io.hyperfoil.tools.horreum.svc.UserServiceImpl.getTeamPrefix;
import static java.util.stream.Collectors.toList;
import static java.util.stream.Collectors.toSet;

/**
 * Implementation of {@link UserBackEnd} that uses Horreum database for storage.
 * <p>
 * Relies on the {@link UserInfo} entity and it's mappings.
 */
@ApplicationScoped
@LookupIfProperty(name = "horreum.roles.provider", stringValue = "database")
public class DatabaseUserBackend implements UserBackEnd {

    private static final Logger LOG = Logger.getLogger(DatabaseUserBackend.class);

    private static UserService.UserData toUserInfo(UserInfo info) {
        return new UserService.UserData("", info.username, info.fistName, info.lastName, info.email);
    }

    @WithRoles(extras = Roles.HORREUM_SYSTEM)
    @Override public List<UserService.UserData> searchUsers(String query) {
        List<UserInfo> users = UserInfo.list("username like ?1", "%" + query + "%");
        return users.stream().map(DatabaseUserBackend::toUserInfo).collect(toList());
    }

    @WithRoles(extras = Roles.HORREUM_SYSTEM)
    @Override public List<UserService.UserData> info(List<String> usernames) {
        List<UserInfo> users = UserInfo.list("username in ?1", usernames);
        return users.stream().map(DatabaseUserBackend::toUserInfo).collect(toList());
    }

    @Transactional
    @WithRoles(fromParams = NewUserParameterConverter.class)
    @Override public void createUser(UserService.NewUser user) {
        Optional<UserInfo> storedUserInfo = UserInfo.findByIdOptional(user.user.username);
        UserInfo userInfo = storedUserInfo.orElseGet(() -> new UserInfo(user.user.username));
        userInfo.email = user.user.email;
        userInfo.fistName = user.user.firstName;
        userInfo.lastName = user.user.lastName;
        userInfo.setPassword(user.password);

        String teamName = user.team.substring(0, user.team.length() - 5);
        if (teamName != null) {
            for (String role : user.roles) {
                if ("viewer".equals(role)) {
                    addTeamMembership(userInfo, teamName, TeamRole.TEAM_VIEWER);
                } else if ("tester".equals(role)) {
                    addTeamMembership(userInfo, teamName, TeamRole.TEAM_TESTER);
                } else if ("uploader".equals(role)) {
                    addTeamMembership(userInfo, teamName, TeamRole.TEAM_UPLOADER);
                } else if ("manager".equals(role)) {
                    addTeamMembership(userInfo, teamName, TeamRole.TEAM_MANAGER);
                } else if ("admin".equals(role)) {
                    userInfo.roles.add(UserRole.ADMIN);
                } else {
                    LOG.infov("Dropping role {0} for user {1} {2}", role, userInfo.fistName, userInfo.lastName);
                }
            }
        }
        userInfo.persist();
    }

    private void addTeamMembership(UserInfo userInfo, String teamName, TeamRole role) {
        Optional<Team> storedTeam = Team.find("teamName", teamName).firstResultOptional();
        userInfo.teams.add(new TeamMembership(userInfo, storedTeam.orElseGet(() -> Team.getEntityManager().merge(new Team(teamName))), role));
    }

    @Override public List<String> getTeams() {
        List<Team> teams = Team.listAll();
        return teams.stream().map(t -> t.teamName + "-team").collect(toList());
    }

    @WithRoles(extras = Roles.HORREUM_SYSTEM)
    @Override public Map<String, List<String>> teamMembers(String team) {
        Team teamEntity = Team.find("teamName", team.substring(0, team.length() - 5)).firstResult();
        if (teamEntity == null) {
            throw ServiceException.notFound("The team " + team + " does not exist");
        }

        Map<String, List<String>> userMap = new HashMap<>();
        teamEntity.teams.forEach(membership -> userMap.computeIfAbsent(membership.user.username, s -> new ArrayList<>()).add(membership.asUIRole()));
        return userMap;
    }

    @Transactional
    @WithRoles(fromParams = UpdateTeamMembersParameterConverter.class)
    @Override public void updateTeamMembers(String team, Map<String, List<String>> roles) {
        Team teamEntity = Team.find("teamName", team.substring(0, team.length() - 5)).firstResult();
        if (teamEntity == null) {
            throw ServiceException.notFound("The team " + team + " does not exist");
        }

        roles.forEach((username, teamRoles) -> {
            Optional<UserInfo> user = UserInfo.findByIdOptional(username);
            user.ifPresent(u -> {
                List<TeamMembership> removedMemberships = u.teams.stream().filter(t -> t.team == teamEntity && !teamRoles.contains(t.asUIRole())).toList();
                removedMemberships.forEach(TeamMembership::delete);
                u.teams.removeAll(removedMemberships);

                u.teams.addAll(teamRoles.stream().map(uiRole -> TeamMembership.getEntityManager().merge(new TeamMembership(user.get(), teamEntity, uiRole))).collect(toSet()));
            });
        });
    }

    @WithRoles(extras = Roles.HORREUM_SYSTEM)
    @Override public List<String> getAllTeams() {
        List<Team> teams = Team.listAll();
        return teams.stream().map(t -> t.teamName + "-team").collect(toList());
    }

    @Transactional
    @WithRoles(extras = Roles.HORREUM_SYSTEM)
    @Override public void addTeam(String team) {
        String prefix = getTeamPrefix(team); // perform validation of the team name
        Team.getEntityManager().merge(new Team(prefix.substring(0, prefix.length() - 1)));
    }

    @Transactional
    @WithRoles(extras = Roles.HORREUM_SYSTEM)
    @Override public void deleteTeam(String team) {
        String prefix = getTeamPrefix(team);
        Team teamEntity = Team.find("teamName", prefix.substring(0, prefix.length() - 1)).firstResult();
        if (teamEntity == null) {
            throw ServiceException.notFound("The team " + team + " does not exist");
        }
        TeamMembership.delete("team", teamEntity);
        teamEntity.delete();
    }

    @WithRoles(extras = Roles.HORREUM_SYSTEM)
    @Override public List<UserService.UserData> administrators() {
        return getAdministratorUsers().stream().map(DatabaseUserBackend::toUserInfo).collect(toList());
    }

    @Transactional
    @WithRoles(extras = Roles.HORREUM_SYSTEM)
    @Override public void updateAdministrators(List<String> newAdmins) {
        getAdministratorUsers().forEach(u -> {
            if (!newAdmins.contains(u.username)) {
                u.roles.remove(UserRole.ADMIN);
                u.persist();
                LOG.infov("Removed administrator role from user {0}", u.username);
            }
        });
        newAdmins.forEach(username -> {
            Optional<UserInfo> user = UserInfo.findByIdOptional(username);
            user.ifPresent(u -> {
                u.roles.add(UserRole.ADMIN);
                u.persist();
                LOG.infov("Added administrator role to user {0}", username);
            });
        });
    }

    private List<UserInfo> getAdministratorUsers() {
        CriteriaBuilder cb = UserInfo.getEntityManager().getCriteriaBuilder();
        CriteriaQuery<UserInfo> query = cb.createQuery(UserInfo.class);
        query.where(cb.isMember(UserRole.ADMIN, query.from(UserInfo.class).get("roles")));
        return UserInfo.getEntityManager().createQuery(query).getResultList();
    }

    /**
     * Extracts username from parameters of `createUser()`
     */
    public static final class NewUserParameterConverter implements Function<Object[], String[]> {
        @Override public String[] apply(Object[] objects) {
            return new String[] { ((UserService.NewUser) objects[0]).user.username };
        }
    }

    /**
     * Extract usernames from parameters of `updateTeamMembers()`
     */
    public static final class UpdateTeamMembersParameterConverter implements Function<Object[], String[]> {
        @SuppressWarnings("unchecked")
        @Override public String[] apply(Object[] objects) {
            return ((Map<String, List<String>>) objects[1]).keySet().toArray(new String[0]);
        }
    }
}
