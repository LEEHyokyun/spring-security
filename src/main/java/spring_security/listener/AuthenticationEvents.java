package spring_security.listener;

import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.*;
import org.springframework.stereotype.Component;
import spring_security.event.CustomizedAuthenticationFailureEvent;
import spring_security.event.CustomizedAuthenticationSuccessEvent;

@Component
public class AuthenticationEvents {
    @EventListener
    public void onSuccess(AuthenticationSuccessEvent success) {
        System.out.println("Authentication SuccessEvent is published : success = " + success.getAuthentication().getName());
    }

    @EventListener
    public void onFailure(AbstractAuthenticationFailureEvent failures) {
        System.out.println("AbstractAuthenticationFailureEvent FailureEvent is published : failures = " + failures.getException().getMessage());
    }

    @EventListener
    public void onSuccess(InteractiveAuthenticationSuccessEvent success) {
        System.out.println("InteractiveAuthenticationSuccessEvent SuccessEvent is published : success = " + success.getAuthentication().getName());
    }

    @EventListener
    public void onSuccess(CustomizedAuthenticationSuccessEvent success) {
        System.out.println("CustomizedAuthenticationSuccessEvent SuccessEvent is published : success = " + success.getAuthentication().getName());
    }

    @EventListener
    public void onFailure(AuthenticationFailureBadCredentialsEvent failures) {
        System.out.println("AuthenticationFailureBadCredentialsEvent FailureEvent is published : failures = " + failures.getException().getMessage());
    }

    @EventListener
    public void onFailure(AuthenticationFailureProviderNotFoundEvent failures) {
        System.out.println("AuthenticationFailureProviderNotFoundEvent FailureEvent is published : failures = " + failures.getException().getMessage());
    }

    @EventListener
    public void onFailure(CustomizedAuthenticationFailureEvent failures) {
        System.out.println("CustomizedAuthenticationFailureEvent FailureEvent is published : failures = " + failures.getException().getMessage());
    }
}