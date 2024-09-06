package io.hyperfoil.tools.horreum.entity.user;

import io.hyperfoil.tools.horreum.api.internal.services.UserService;
import io.quarkus.hibernate.orm.panache.PanacheEntityBase;
import jakarta.persistence.Entity;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.NamedQueries;
import jakarta.persistence.NamedQuery;
import jakarta.persistence.SequenceGenerator;
import jakarta.persistence.Table;
import jakarta.persistence.Transient;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDate;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Comparator;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Stream;

import static jakarta.persistence.GenerationType.SEQUENCE;

@Entity
@Table(name = "userinfo_apikey")
@NamedQueries({
        @NamedQuery(name = "UserApiKey.access", query = "from UserApiKey where not revoked AND (access is null AND creation = ?1 OR access = ?1)"),
        @NamedQuery(name = "UserApiKey.accessBefore", query = "from UserApiKey where not revoked AND (access is null AND creation < ?1 OR access < ?1)"),
})
public class UserApiKey extends PanacheEntityBase implements Comparable<UserApiKey> {

    // old authentication tokens are not listed and can't be renewed either
    // they are kept around to prevent re-use
    public static long HIDE_AFTER_DAYS = 7;

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
            name = "apikeyIdGenerator",
            sequenceName = "userinfo_apikey_id_seq",
            allocationSize = 1
    )
    @GeneratedValue(strategy = SEQUENCE, generator = "apikeyIdGenerator")
    public long id;

    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "username")
    public UserInfo user;

    @Transient
    private final UUID randomnessSource;

    private final String hash;

    public String name;

    @Enumerated
    public final UserService.KeyType type;

    public LocalDate creation, access;

    public long valid; // number of days after last access that the key remains valid

    public boolean revoked;

    public UserApiKey() {
        randomnessSource = null;
        hash = null;
        name = null;
        type = UserService.KeyType.USER;
    }

    public UserApiKey(UserService.ApiKeyRequest request, LocalDate creation, long valid) {
        this(request.name, request.type, creation, valid);
    }

    public UserApiKey(String name, UserService.KeyType type, LocalDate creationDate, long valid) {
        randomnessSource = UUID.randomUUID();
        this.name = name;
        this.type = type;
        this.valid = valid;
        hash = computeHash(keyString());
        creation = creationDate;
        revoked = false;
    }

    public boolean isHidden(LocalDate givenDay) {
        return givenDay.isBefore((access == null ? creation : access).plusDays(valid + HIDE_AFTER_DAYS));
    }

    private long toExpiration(LocalDate givenDay) {
        return valid - ChronoUnit.DAYS.between(access == null ? creation : access, givenDay);
    }

    // --- //

    public String keyString() {
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
        builder.append(randomnessSource.toString().replace("-", "_").toUpperCase()); // keep the dashes for quick validation of key format
        return builder.toString();
    }

    public static Optional<UserApiKey> findOptional(String key) {
        // validate key structure before computing hash
        if (key.startsWith("H") && Stream.of(4, 13, 18, 23, 28).allMatch(i -> key.charAt(i) == '_')) {
            return UserApiKey.<UserApiKey>find("hash", computeHash(key)).firstResultOptional();
        } else {
            return Optional.empty();
        }
    }

    private static String computeHash(String key) {
        return Base64.getEncoder().encodeToString(digest.digest(key.getBytes()));
    }

    // --- //

    @Override public boolean equals(Object o) {
        if (this == o) {
            return true;
        } else if (o == null || getClass() != o.getClass()) {
            return false;
        }
        return Objects.equals(this.id, ((UserApiKey) o).id) && Objects.equals(this.hash, ((UserApiKey) o).hash);
    }

    @Override public int hashCode() {
        return Objects.hash(id, hash);
    }

    public UserService.ApiKeyResponse toResponse() {
        UserService.ApiKeyResponse response = new UserService.ApiKeyResponse();
        response.id = id;
        response.name = name;
        response.type = type;
        response.creation = creation;
        response.access = access;
        response.isRevoked = revoked;
        response.toExpiration = toExpiration(LocalDate.now());
        return response;
    }

    @Override public int compareTo(UserApiKey other) {
        return Comparator.<UserApiKey, LocalDate>comparing(a -> a.creation).thenComparing(a -> a.name).compare(this, other);
    }
}
