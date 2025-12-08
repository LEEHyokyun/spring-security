package spring_security.authorization;

import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;

import java.util.function.Supplier;

public class CustomizedAuthorizationManager implements AuthorizationManager<RequestAuthorizationContext> {

    private static final String REQUIRED_ROLE = "ROLE_ADMIN";

    @Override
    public AuthorizationDecision check(Supplier<Authentication> authentication, RequestAuthorizationContext object) {
        Authentication authenticationInfo = authentication.get();

        if(authenticationInfo == null || !authenticationInfo.isAuthenticated() || authenticationInfo instanceof AnonymousAuthenticationToken) {
            return new AuthorizationDecision(false);
        }

        boolean isAuthorizied = authenticationInfo.getAuthorities().stream().anyMatch(authority ->
            REQUIRED_ROLE.equals(authority.getAuthority())
        );

        return new AuthorizationDecision(isAuthorizied);
    }
}
