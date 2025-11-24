package spring_security.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.CurrentSecurityContext;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import spring_security.service.SecurityContextService;

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

//    @GetMapping("/")
//    public String index(String customParam) {
//        if(customParam != null){
//            return "customPage"; //login 성공시 reqeustCache에 의해 저장된 쿼리스트링이 그대로 적용됨
//        }else{
//            return "index";
//        }
//        /*
//        * 최초) SecurityProperties가 생성하여 memory에 저장한 계정을 인증정보로 사용
//        * - user / generated password
//        * get request) SpringBootWebSecurityConfiguration에서 ConditionalOnDefaultWebSecurity의 조건이 참인 여부를 판단
//        * DefaultWebSecurityCondition의 Class/Bean 조건의 참 여부를 판단하여
//        * 최종 참 판단 시 SpringBootWebSecurityConfiguration의 defaultSecurityFilterChain을 최종 실행
//        * 인증 및 인가여부를 확인하고
//        * 폼로그인 및 httpBasic 방식을 통해 인증 진행
//        * 인증 승인 후 http build 최종 진행
//        * */
//        //return "index";
//    }
    final SecurityContextService securityContextService;

    @GetMapping("/")
    public String index() {
        //현재 인증상태
        SecurityContext securityContext = SecurityContextHolder.getContextHolderStrategy().getContext();
        Authentication authentication = securityContext.getAuthentication();
        System.out.println("Controller authetication : " + authentication);

        securityContextService.securityContext();

        return "index";
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
