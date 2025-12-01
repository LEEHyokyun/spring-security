package spring_security.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.CurrentSecurityContext;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import spring_security.service.SessionInformService;

/*
* TIP
*
** @Controller
* 주 역할: 명함 역할 (Spring MVC Controller 계층임을 알림)
* 반환값은 기본적으로 문자열을 "뷰 이름"으로 해석
* 즉, return "home"; → home.jsp 혹은 home.html 등을 찾아 렌더링함.

** @RestController
* @Controller + @ResponseBody 조합
* 반환되는 값은 View 렌더링이 아닌, 응답 Body(JSON/Text 등)에 그대로 작성
* 주로 REST API 엔드포인트에서 사용
* */
@RestController
@RequiredArgsConstructor
public class IndexController {

    private final SessionInformService sessionInformService;

    @GetMapping("/")
    public String index() {
        return "index";
    }

    @GetMapping("/sessionInfo")
    public String sessionInfo(){
        sessionInformService.sessionInform();
        return "sessionInfo";
    }

    @GetMapping("/invalid")
    public String invalid() {
        return "invalid";
    }

    @GetMapping("/home")
    public String home() {
        return "home";
    }

    @GetMapping("/loginPage")
    public String loginPage() {
        return "loginPage";
    }

    @GetMapping("/anonymous")
    public String anonymous() { return "anonymous"; }

    //누구든 접근 가능
    @GetMapping("/authentication")
    public String authentication(Authentication authentication) {
        //from security context
        if(authentication instanceof AnonymousAuthenticationToken) { //무조건 들어있음
            return "anonymous";
        }else{
            return "not anonymous"; //UsernamePasswordAuthenticationToken or 구현객체
        }
    }

    //누구든 접근 가능
    //securityContext에서 추출 -> 가장 확실하고 안전.
    @GetMapping("/anonymousContext")
    //form security context
    public String anonymousContext(@CurrentSecurityContext SecurityContext securityContext) {
        return securityContext.getAuthentication().getName(); //guest
    }

    @GetMapping("/logoutSuccess")
    public String logoutSuccess() {
        return "logoutSuccess";
    }

}
