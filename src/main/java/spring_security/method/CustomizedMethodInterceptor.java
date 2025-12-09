package spring_security.method;

import lombok.RequiredArgsConstructor;
import org.aopalliance.intercept.MethodInterceptor;
import org.aopalliance.intercept.MethodInvocation;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;

import java.nio.file.AccessDeniedException;

@RequiredArgsConstructor
public class CustomizedMethodInterceptor implements MethodInterceptor {

    //AOP처리
    private final AuthorizationManager<MethodInvocation>  authorizationManager;

    @Override
    public Object invoke(MethodInvocation invocation) throws Throwable {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if(authorizationManager.check(()-> authentication, invocation).isGranted()){
            return invocation.proceed(); //method 호출
        }

        throw new AccessDeniedException("Access denied");
    }
}
