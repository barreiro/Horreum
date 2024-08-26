package io.hyperfoil.tools.auth;

import jakarta.ws.rs.client.ClientRequestContext;
import jakarta.ws.rs.client.ClientRequestFilter;
import org.jboss.logging.Logger;

public class HorreumTokenAuthentication implements ClientRequestFilter {

    // sync with io.hyperfoil.tools.horreum.server.AuthenticationTokenMechanism
    public static final String HORREUM_AUTHENTICATION_TOKEN_HEADER = "X-Horreum-Authentication-Token";

    private static final Logger LOG = Logger.getLogger(HorreumTokenAuthentication.class);
    private boolean showAuthMethod = true;

    private final String authenticationToken;

    public HorreumTokenAuthentication(String token) {
        authenticationToken = token;
    }

    public void filter(ClientRequestContext requestContext) {
        if (showAuthMethod) {
            LOG.infov("Authentication with Horreum token");
            showAuthMethod = false;
        }
        requestContext.getHeaders().putSingle(HORREUM_AUTHENTICATION_TOKEN_HEADER, this.authenticationToken);
    }
}
