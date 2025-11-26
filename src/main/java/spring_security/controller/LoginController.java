package spring_security.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jdk.jfr.Registered;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import spring_security.customized.LoginRequest;

import java.util.List;

@RestController
@RequiredArgsConstructor
public class LoginController {

    //인증수행
    private final AuthenticationManager authenticationManager;

    //Repository
    private final HttpSessionSecurityContextRepository httpSessionSecurityContextRepository = new HttpSessionSecurityContextRepository();

//    @PostMapping("/login")
//    public Authentication login(@RequestParam("username") String username, @RequestParam("password") String password) {
//        return new Authentication();
//    }

    @PostMapping("/login")
    public Authentication login(@RequestBody LoginRequest loginRequest, HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse){
        //token -> authenticate -> authentication
        UsernamePasswordAuthenticationToken token = UsernamePasswordAuthenticationToken.unauthenticated(loginRequest.getUsername(), loginRequest.getPassword());
        Authentication authentication = authenticationManager.authenticate(token); //token 인증시도 -> 인증객체 반환

        //authentication -> securityContext / securityContextHolder / threadLocal
        SecurityContext securityContext = SecurityContextHolder.getContextHolderStrategy().getContext();
        securityContext.setAuthentication(authentication);
        SecurityContextHolder.getContextHolderStrategy().setContext(securityContext);

        //securityContext -> session (*repository)
        httpSessionSecurityContextRepository.saveContext(securityContext, httpServletRequest, httpServletResponse);

        return authentication;
    }

}
