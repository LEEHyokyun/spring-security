package spring_security.service;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.session.SessionInformation;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class SessionInformService {

    private final SessionRegistry sessionRegistry;

    public void sessionInform(){
        List<Object> allPrinciples = sessionRegistry.getAllPrincipals();

        for(Object principle:allPrinciples){
            List<SessionInformation> sessionInforms = sessionRegistry.getAllSessions(principle,false);
            for(SessionInformation sessionInformation : sessionInforms){
                System.out.println(sessionInformation.getPrincipal() + " " + sessionInformation.getSessionId());
            }
        }
    }
}
