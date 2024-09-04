package io.hyperfoil.tools.horreum.entity.user;

import io.hyperfoil.tools.horreum.api.internal.services.UserService;
import io.quarkus.hibernate.orm.panache.PanacheEntityBase;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.SequenceGenerator;
import jakarta.persistence.Transient;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDate;
import java.util.Base64;
import java.util.Comparator;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Stream;

import static jakarta.persistence.GenerationType.SEQUENCE;

@Entity(name = "userinfo_token")
public class AuthenticationToken extends PanacheEntityBase implements Comparable<AuthenticationToken> {

    // old authentication tokens are not listed and can't be renewed either
    // they are kept around to prevent re-use
    public static long OLD_EXPIRATION_DAYS = 7;

    private static MessageDigest digest;

    static {
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            // ignore
        }
    }

    @Id
    @SequenceGenerator(
            name = "authenticationTokenIdGenerator",
            sequenceName = "userinfo_token_id_seq",
            allocationSize = 1
    )
    @GeneratedValue(strategy = SEQUENCE, generator = "authenticationTokenIdGenerator")
    @Column(name = "id")
    public Integer id;

    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "username")
    public UserInfo user;

    @Transient private final UUID token;

    private final String hash;

    private final String name;

    @Enumerated
    public final UserService.HorreumAuthenticationTokenType type;

    @Column(name = "date_created")
    private LocalDate dateCreated;
    @Column(name = "date_expired")
    private LocalDate dateExpired;
    @Column(name = "last_access")
    private LocalDate lastAccess;
    private boolean revoked;

    public AuthenticationToken() {
    }

    public AuthenticationToken(UserService.HorreumAuthenticationTokenRequest request) {
        this(request.name, request.expiration, request.type);
    }

    public AuthenticationToken(String name, long expiration, UserService.HorreumAuthenticationTokenType type) {
        token = UUID.randomUUID();
        this.name = name;
        this.type = type;
        hash = computeHash(getTokenString());
        dateCreated = LocalDate.now();
        dateExpired = LocalDate.now().plusDays(expiration);
        revoked = false;
    }

    public String getName() {
        return name;
    }

    public String getTokenString() {
        StringBuilder builder = new StringBuilder(50);
        builder.append("H");
        switch (type) {
            case USER:
                builder.append("USR");
                break;
            default:
                builder.append("UNK");
        }
        builder.append("_");
        builder.append(token.toString().replace("-", "_").toUpperCase());
        return builder.toString();
    }

    public boolean isOld() {
        return dateExpired.plusDays(OLD_EXPIRATION_DAYS).isBefore(LocalDate.now());
    }

    public boolean isExpired() {
        return LocalDate.now().isAfter(dateExpired);
    }

    public boolean isValid() {
        if (isRevoked() || isExpired()) {
            return false;
        } else {
            lastAccess = LocalDate.now();
            return true;
        }
    }

    public boolean isRevoked() {
        return revoked;
    }

    public void revoke() {
        revoked = true;
        dateExpired = LocalDate.now();
    }

    public void renew(long days) {
        if (isOld()) {
            throw new IllegalStateException("Token has expired long ago and cannot be renewed");
        }
        dateExpired = LocalDate.now().plusDays(days);
    }

    // --- //

    private static String computeHash(String token) {
        return Base64.getEncoder().encodeToString(digest.digest(token.getBytes()));
    }

    public static Optional<AuthenticationToken> findValid(String token) {
        // validate token structure before computing hash
        if (token.startsWith("H") && Stream.of(4,13,18,23,28).allMatch(i -> token.charAt(i) == '_')) {
            return AuthenticationToken.<AuthenticationToken>find("hash", computeHash(token)).firstResultOptional().filter(AuthenticationToken::isValid);
        }  else {
            return Optional.empty();
        }
    }

    // --- //

    @Override public boolean equals(Object o) {
        if (this == o) {
            return true;
        } else if (o == null || getClass() != o.getClass()) {
            return false;
        }
        return Objects.equals(this.id, ((AuthenticationToken) o).id) && Objects.equals(this.token, ((AuthenticationToken) o).token);
    }

    @Override public int hashCode() {
        return Objects.hash(id, token);
    }

    public UserService.HorreumAuthenticationToken toHorreumAuthenticationToken() {
        UserService.HorreumAuthenticationToken token = new UserService.HorreumAuthenticationToken();
        token.id = id;
        token.name = name;
        token.type = type;
        token.dateCreated = dateCreated;
        token.dateExpired = dateExpired;
        token.lastAccess = lastAccess;
        token.isExpired = isExpired();
        token.isRevoked = isRevoked();
        return token;
    }

    @Override public int compareTo(AuthenticationToken other) {
        return Comparator.<AuthenticationToken, LocalDate>comparing(a -> a.dateCreated).thenComparing(a -> a.name).compare(this, other);
    }
}
