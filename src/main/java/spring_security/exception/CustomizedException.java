package spring_security.exception;

import org.springframework.security.core.AuthenticationException;

public class CustomizedException extends AuthenticationException {
    public CustomizedException(String explanation) {
        super(explanation);
    }
}
