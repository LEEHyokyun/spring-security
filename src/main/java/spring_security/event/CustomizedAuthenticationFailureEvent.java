package spring_security.event;

import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

public class CustomizedAuthenticationFailureEvent extends AbstractAuthenticationFailureEvent {

    public CustomizedAuthenticationFailureEvent(Authentication authentication, AuthenticationException exception) {
        super(authentication, exception);
    }
}
