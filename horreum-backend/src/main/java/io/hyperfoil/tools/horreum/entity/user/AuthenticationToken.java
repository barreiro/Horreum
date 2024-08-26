package io.hyperfoil.tools.horreum.entity.user;

import io.hyperfoil.tools.horreum.api.internal.services.UserService;
import io.quarkus.hibernate.orm.panache.PanacheEntityBase;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.SequenceGenerator;

import java.time.LocalDate;
import java.time.temporal.ChronoUnit;
import java.util.Objects;
import java.util.UUID;

import static jakarta.persistence.GenerationType.SEQUENCE;

@Entity(name = "userinfo_token")
public class AuthenticationToken extends PanacheEntityBase {

    public static long DEFAULT_EXPIRATION_DAYS = 400;

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

    private final UUID token;

    private final String name;

    @Column(name = "date_expired")
    private final LocalDate dateExpired;
    private boolean revoked;

    public AuthenticationToken() {
        this("");
    }

    public AuthenticationToken(String tokenName) {
        this(tokenName, DEFAULT_EXPIRATION_DAYS);
    }

    public AuthenticationToken(String tokenName, long expiration) {
        token = UUID.randomUUID();
        name = tokenName;
        dateExpired = LocalDate.now().plusDays(expiration);
        revoked = false;
    }

    public String getName() {
        return name;
    }

    public String getToken() {
        return token.toString();
    }

    public boolean isExpired() {
        return LocalDate.now().isAfter(dateExpired);
    }

    public long daysToExpiration() {
        return ChronoUnit.DAYS.between(LocalDate.now(), dateExpired);
    }

    public boolean isValid() {
        return !(isRevoked() || isExpired());
    }

    public boolean isRevoked() {
        return revoked;
    }

    public void revoke() {
        revoked = true;
    }

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
        token.dateExpired = dateExpired;
        token.isExpired = isExpired();
        token.isRevoked = isRevoked();
        return token;
    }

}
