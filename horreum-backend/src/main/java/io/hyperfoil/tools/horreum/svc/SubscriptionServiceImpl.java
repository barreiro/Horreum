package io.hyperfoil.tools.horreum.svc;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.annotation.security.RolesAllowed;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.persistence.EntityManager;
import javax.transaction.Transactional;

import io.hyperfoil.tools.horreum.api.SubscriptionService;
import io.hyperfoil.tools.horreum.entity.alerting.Watch;
import io.quarkus.security.identity.SecurityIdentity;

@ApplicationScoped
public class SubscriptionServiceImpl implements SubscriptionService {
   @Inject
   SqlServiceImpl sqlService;

   @Inject
   EntityManager em;

   @Inject
   SecurityIdentity identity;

   private static Set<String> merge(Set<String> set, String item) {
      if (set == null) {
         set = new HashSet<>();
      }
      set.add(item);
      return set;
   }

   @RolesAllowed({ Roles.TESTER, Roles.ADMIN})
   @Override
   public Map<Integer, Set<String>> all() {
      try (@SuppressWarnings("unused") CloseMe closeMe = sqlService.withRoles(em, identity)) {
         // TODO: do all of this in single obscure PSQL query
         String username = identity.getPrincipal().getName();
         List<Watch> personal = Watch.list("?1 IN elements(users)", username);
         List<Watch> optout = Watch.list("?1 IN elements(optout)", username);
         Set<String> teams = identity.getRoles().stream().filter(role -> role.endsWith("-team")).collect(Collectors.toSet());
         List<Watch> team = Watch.list("FROM watch w LEFT JOIN w.teams teams WHERE teams IN ?1", teams);
         Map<Integer, Set<String>> result = new HashMap<>();
         personal.forEach(w -> result.compute(w.testId, (i, set) -> merge(set, username)));
         optout.forEach(w -> result.compute(w.testId, (i, set) -> merge(set, "!" + username)));
         team.forEach(w -> result.compute(w.testId, (i, set) -> {
            Set<String> nset = new HashSet<>(w.teams);
            nset.retainAll(teams);
            if (set != null) {
               nset.addAll(set);
            }
            return nset;
         }));
         @SuppressWarnings("unchecked")
         Stream<Integer> results = em.createQuery("SELECT id FROM test").getResultStream();
         results.forEach(id -> result.putIfAbsent(id, Collections.emptySet()));
         return result;
      }
   }

   @RolesAllowed({ Roles.TESTER, Roles.ADMIN})
   @Override
   public Watch get(Integer testId) {
      try (@SuppressWarnings("unused") CloseMe closeMe = sqlService.withRoles(em, identity)) {
         Watch watch = Watch.find("testId = ?1", testId).firstResult();
         if (watch == null) {
            watch = new Watch();
            watch.testId = testId;
            watch.teams = Collections.emptyList();
            watch.users = Collections.emptyList();
            watch.optout = Collections.emptyList();
         }
         return watch;
      }
   }

   private static List<String> add(List<String> list, String item) {
      if (list == null) {
         list = new ArrayList<>();
      }
      list.add(item);
      return list;
   }

   @RolesAllowed({Roles.TESTER, Roles.ADMIN})
   @Transactional
   @Override
   public List<String> addUserOrTeam(Integer testId, String userOrTeam) {
      if (testId == null) {
         throw ServiceException.badRequest("Missing test id");
      } else if (userOrTeam == null) {
         throw ServiceException.badRequest("Missing user/team");
      } else if (userOrTeam.startsWith("\"") && userOrTeam.endsWith("\"") && userOrTeam.length() > 2) {
         userOrTeam = userOrTeam.substring(1, userOrTeam.length() - 1);
      }
      boolean isTeam = true;
      boolean isOptout = false;
      if (userOrTeam.startsWith("!")) {
         userOrTeam = userOrTeam.substring(1);
         isOptout = true;
      }
      String username = identity.getPrincipal().getName();
      if (userOrTeam.equals("__self") || userOrTeam.equals(username)) {
         userOrTeam = username;
         isTeam = false;
      } else if (!userOrTeam.endsWith("-team") || !identity.getRoles().contains(userOrTeam)) {
         throw ServiceException.badRequest("Wrong user/team: " + userOrTeam);
      }
      if (isTeam && isOptout) {
         throw ServiceException.badRequest("Cannot opt-out team: use remove");
      }
      try (@SuppressWarnings("unused") CloseMe closeMe = sqlService.withRoles(em, identity)) {
         Watch watch = Watch.find("testid", testId).firstResult();
         if (watch == null) {
            watch = new Watch();
            watch.testId = testId;
         }
         if (isOptout) {
            watch.optout = add(watch.optout, userOrTeam);
            if (watch.users != null) {
               watch.users.remove(userOrTeam);
            }
         } else if (isTeam) {
            watch.teams = add(watch.teams, userOrTeam);
         } else {
            watch.users = add(watch.users, userOrTeam);
            if (watch.optout != null) {
               watch.optout.remove(userOrTeam);
            }
         }
         watch.persist();
         return currentWatches(watch);
      }
   }

   @RolesAllowed({Roles.TESTER, Roles.ADMIN})
   @Transactional
   @Override
   public List<String> removeUserOrTeam(Integer testId, String userOrTeam) {
      if (testId == null) {
         throw ServiceException.badRequest("Missing test id");
      } else if (userOrTeam == null) {
         throw ServiceException.badRequest("Missing user/team");
      } else if (userOrTeam.startsWith("\"") && userOrTeam.endsWith("\"") && userOrTeam.length() > 2) {
         userOrTeam = userOrTeam.substring(1, userOrTeam.length() - 1);
      }
      try (@SuppressWarnings("unused") CloseMe closeMe = sqlService.withRoles(em, identity)) {
         Watch watch = Watch.find("testid", testId).firstResult();
         if (watch == null) {
            return Collections.emptyList();
         }
         boolean isOptout = false;
         if (userOrTeam.startsWith("!")) {
            isOptout = true;
            userOrTeam = userOrTeam.substring(1);
         }
         String username = identity.getPrincipal().getName();
         if (userOrTeam.equals("__self") || userOrTeam.equals(username)) {
            if (isOptout) {
               if (watch.optout != null) {
                  watch.optout.remove(userOrTeam);
               }
            } else if (watch.users != null) {
               watch.users.remove(username);
            }
         } else if (userOrTeam.endsWith("-team") && identity.getRoles().contains(userOrTeam)) {
            if (isOptout) {
               throw ServiceException.badRequest("Team cannot be opted out.");
            }
            if (watch.teams != null) {
               watch.teams.remove(userOrTeam);
            }
         } else {
            throw ServiceException.badRequest("Wrong user/team: " + userOrTeam);
         }
         watch.persist();
         return currentWatches(watch);
      }
   }

   @RolesAllowed({Roles.TESTER, Roles.ADMIN})
   @Transactional
   @Override
   public void update(Integer testId, Watch watch) {
      try (@SuppressWarnings("unused") CloseMe closeMe = sqlService.withRoles(em, identity)) {
         Watch existing = Watch.find("testid", testId).firstResult();
         if (existing == null) {
            watch.id = null;
            watch.testId = testId;
            watch.persistAndFlush();
         } else {
            existing.users = watch.users;
            existing.optout = watch.optout;
            existing.teams = watch.teams;
            existing.persistAndFlush();
         }
      }
   }

   private List<String> currentWatches(Watch watch) {
      ArrayList<String> own = new ArrayList<>(identity.getRoles());
      String username = identity.getPrincipal().getName();
      own.add(username);
      ArrayList<String> all = new ArrayList<>();
      if (watch.teams != null) {
         all.addAll(watch.teams);
      }
      if (watch.users != null) {
         all.addAll(watch.users);
      }
      all.retainAll(own);
      if (watch.optout != null && watch.optout.contains(username)) {
         all.add("!" + username);
      }
      return all;
   }
}