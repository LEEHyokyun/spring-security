package spring_security.event;

import org.springframework.security.authentication.event.AbstractAuthenticationEvent;
import org.springframework.security.core.Authentication;

public class CustomizedAuthenticationSuccessEvent extends AbstractAuthenticationEvent {
    public CustomizedAuthenticationSuccessEvent(Authentication authentication) {
        super(authentication);
    }
}
