//package spring_security.customized;
//
//import org.springframework.security.authentication.AuthenticationProvider;
//import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
//import org.springframework.security.core.Authentication;
//import org.springframework.security.core.AuthenticationException;
//import org.springframework.security.core.authority.SimpleGrantedAuthority;
//
//import java.util.List;
//
//public class CustomizedAuthenticationProvider implements AuthenticationProvider {
//    @Override
//    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
//
//        String loginId = authentication.getName();
//        String password = (String) authentication.getCredentials();
//
//        return new UsernamePasswordAuthenticationToken(loginId, password, List.of(new SimpleGrantedAuthority("ROLE_USER")));
//    }
//
//    @Override
//    public boolean supports(Class<?> authentication) {
//        //무조건 회피
//        return false;
//    }
//}
