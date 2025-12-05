package spring_security.config;

import org.springframework.security.access.expression.method.MethodSecurityExpressionOperations;
import org.springframework.stereotype.Component;

@Component("authorizer")
public class CustomizedAuthorizer {
    public boolean isUser(MethodSecurityExpressionOperations root){
        boolean decision = root.hasAuthority("ROLE_USER");
        return decision;
    }
}
