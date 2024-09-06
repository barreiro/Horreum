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

@Entity(name = "userinfo_apikey")
public class ApiKey extends PanacheEntityBase implements Comparable<ApiKey> {

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
    private final UUID token;

    private final String hash;

    private String name;

    @Enumerated
    public final UserService.KeyType type;

    private LocalDate creation, access, expiration;

    private boolean revoked;

    public ApiKey() {
        token = null;
        hash = null;
        name = null;
        type = UserService.KeyType.USER;
    }

    public ApiKey(UserService.ApiKeyRequest request) {
        this(request.name, request.expiration, request.type);
    }

    public ApiKey(String name, long days, UserService.KeyType type) {
        token = UUID.randomUUID();
        this.name = name;
        this.type = type;
        hash = computeHash(keyString());
        creation = LocalDate.now();
        expiration = LocalDate.now().plusDays(days);
        revoked = false;
    }

    public String getName() {
        return name;
    }

    public void setName(String newName) {
        name = newName;
    }

    public LocalDate getCreation() {
        return creation;
    }

    public LocalDate getAccess() {
        return access;
    }
    
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
        builder.append(token.toString().replace("-", "_").toUpperCase()); // keep the dashes for quick validation of key format
        return builder.toString();
    }

    public boolean isOld() {
        return expiration.plusDays(OLD_EXPIRATION_DAYS).isBefore(LocalDate.now());
    }

    public boolean isExpired() {
        return LocalDate.now().isAfter(expiration);
    }

    public boolean isValid() {
        if (isRevoked() || isExpired()) {
            return false;
        } else {
            access = LocalDate.now();
            return true;
        }
    }

    public boolean isRevoked() {
        return revoked;
    }

    public void revoke() {
        revoked = true;
        expiration = LocalDate.now();
    }

    public void renew(long days) {
        if (isOld()) {
            throw new IllegalStateException("Token has expired long ago and cannot be renewed");
        }
        expiration = LocalDate.now().plusDays(days);
    }

    // --- //

    private static String computeHash(String key) {
        return Base64.getEncoder().encodeToString(digest.digest(key.getBytes()));
    }

    public static Optional<ApiKey> findValid(String key) {
        // validate key structure before computing hash
        if (key.startsWith("H") && Stream.of(4,13,18,23,28).allMatch(i -> key.charAt(i) == '_')) {
            return io.hyperfoil.tools.horreum.entity.user.ApiKey.<ApiKey>find("hash", computeHash(key)).firstResultOptional().filter(ApiKey::isValid);
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
        return Objects.equals(this.id, ((ApiKey) o).id) && Objects.equals(this.hash, ((ApiKey) o).hash);
    }

    @Override public int hashCode() {
        return Objects.hash(id, hash);
    }

    public UserService.ApiKeyResponse toResponse() {
        UserService.ApiKeyResponse token = new UserService.ApiKeyResponse();
        token.id = id;
        token.name = name;
        token.type = type;
        token.creation = creation;
        token.access = access;
        token.expiration = expiration;
        token.isExpired = isExpired();
        token.isRevoked = isRevoked();
        return token;
    }

    @Override public int compareTo(ApiKey other) {
        return Comparator.<ApiKey, LocalDate>comparing(a -> a.creation).thenComparing(a -> a.name).compare(this, other);
    }
}
