package spring_security.config;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.aspectj.apache.bcel.classfile.Module;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AnonymousAuthenticationProvider;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.rememberme.TokenBasedRememberMeServices;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import spring_security.customized.CustomizedUserDetailService;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

@EnableWebSecurity
@Configuration
public class SecurityConfig {
    
    //UserDetailsService 주입
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        /*
         * 최초 : DaoAuthenticationProvider, AnonymousAuthenticationProvider
         * */
      http
                .authorizeRequests(auth -> auth
                        .anyRequest().authenticated())
                .formLogin(Customizer.withDefaults())
        ;

        return http.build();
    }
    
    //formLogin basic1
//    @Bean
//    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//        http
//                .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
//                //.formLogin(Customizer.withDefaults());  //client 요청에 대해 기본 인증방식으로 formLogin 방식을 설정
//                .formLogin(Customizer.withDefaults())
//
//                ;
//
//        return http.build();
//    }

    //formLogin basic2 (providerManager by httpSecurity)
//    @Bean
//    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//
//        //providerManager by httpSecurity
//        AuthenticationManagerBuilder authenticationManagerBuilder = http.getSharedObject(AuthenticationManagerBuilder.class);
//        AuthenticationManager authenticationManager = authenticationManagerBuilder.build();
//
//        //customizing ? authentication Manager / filter 별도 등록.
//        http
//                .authorizeRequests(auth -> auth
//                        .requestMatchers("/", "/api/login").permitAll()
//                        .anyRequest().authenticated())
//                //.formLogin(Customizer.withDefaults())
//                .authenticationManager(authenticationManager)
//                .addFilterBefore(customAuthenticationFilter(http, authenticationManager), UsernamePasswordAuthenticationFilter.class)
//                ;
//
//
//
//        return http.build();
//    }

    //formLogin basic3 (직접 생성)
//    @Bean
//    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//
//        //customizing ? authentication Manager / filter / provider 모두 별도 등록.
//        http
//                .authorizeRequests(auth -> auth
//                        .requestMatchers("/", "/api/login").permitAll()
//                        .anyRequest().authenticated())
//                //.formLogin(Customizer.withDefaults())
//                .addFilterBefore(customAuthenticationFilter(http), UsernamePasswordAuthenticationFilter.class)
//        ;
//
//
//
//        return http.build();
//    }

    //filter만 생성해줄 시
//    public CustomAuthenticationFilter customAuthenticationFilter(HttpSecurity http, AuthenticationManager authenticationManager) throws Exception {
//        CustomAuthenticationFilter customAuthenticationFilter = new CustomAuthenticationFilter(http);
//        customAuthenticationFilter.setAuthenticationManager(authenticationManager);
//        return customAuthenticationFilter;
//    }

    //provider 직접 생성 시
//    public CustomAuthenticationFilter customAuthenticationFilter(HttpSecurity http) throws Exception {
//        List<AuthenticationProvider> authenticationProviders = List.of(new DaoAuthenticationProvider()); //userDetail -- 기본!
//        ProviderManager providerManager = new ProviderManager(authenticationProviders);
//
//        List<AuthenticationProvider> childAuthenticationProviders = List.of(new AnonymousAuthenticationProvider("key"), new CustomAuthenticationProvider());
//        ProviderManager childProviderManager = new ProviderManager(childAuthenticationProviders, providerManager);
//
//        CustomAuthenticationFilter customAuthenticationFilter = new CustomAuthenticationFilter(http);
//        customAuthenticationFilter.setAuthenticationManager(childProviderManager);
//
//        return customAuthenticationFilter;
//    }

    //customized provider 생성 : 직접 생성 시
//    @Bean
//    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//
//        /*
//        * 최초 : DaoAuthenticationProvider, AnonymousAuthenticationProvider
//        * */
//        //way 1 ; 일반객체를 생성하여 그 객체를 주입해준다.
////        AuthenticationManagerBuilder authenticationManagerBuilder = http.getSharedObject(AuthenticationManagerBuilder.class);
////        authenticationManagerBuilder.authenticationProvider(new CustomizedAuthenticationProvider());
////        authenticationManagerBuilder.authenticationProvider(new CustomizedAuthenticationProvider2());
//
//        //wat 2 ; 빈객체(=CustomizedAuthenticationProvider3)
//
//        http
//                .authorizeRequests(auth -> auth
//                        .requestMatchers("/").permitAll()
//                        .anyRequest().authenticated())
//                .formLogin(Customizer.withDefaults())
//        ;
//
//        return http.build();
//    }

    //customized provider 생성 : Bean 생성 및 주입
//    @Bean
//    public SecurityFilterChain securityFilterChain(HttpSecurity http, AuthenticationManagerBuilder builder, AuthenticationConfiguration configuration) throws Exception {
//
//        /*
//         * 최초 : DaoAuthenticationProvider, AnonymousAuthenticationProvider
//         * */
//        //way 1 ; 일반객체를 생성하여 그 객체를 주입해준다.
//    //        AuthenticationManagerBuilder authenticationManagerBuilder = http.getSharedObject(AuthenticationManagerBuilder.class);
//    //        authenticationManagerBuilder.authenticationProvider(new CustomizedAuthenticationProvider());
//    //        authenticationManagerBuilder.authenticationProvider(new CustomizedAuthenticationProvider2());
//
//        //way 2 ; 빈객체(=CustomizedAuthenticationProvider)
//        AuthenticationManagerBuilder authenticationManagerBuilder = http.getSharedObject(AuthenticationManagerBuilder.class);
//        authenticationManagerBuilder.authenticationProvider(authenticationProvider()); //자식측에 customizd provider를 하나 더 추가
//
//        ProviderManager providerManager = (ProviderManager) configuration.getAuthenticationManager();
//        providerManager.getProviders().remove(0); //기존 customized 제거
//        builder.authenticationProvider(new DaoAuthenticationProvider()); //dao 추가
//
//        http
//                .authorizeRequests(auth -> auth
//                        .requestMatchers("/").permitAll()
//                        .anyRequest().authenticated())
//                .formLogin(Customizer.withDefaults())
//        ;
//
//        return http.build();
//    }

    //customized provider 생성 : Bean 생성 및 주입
//    @Bean
//    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//
//        /*
//         * 최초 : DaoAuthenticationProvider, AnonymousAuthenticationProvider
//         * */
//
//        //way 3 ; 빈객체(=CustomizedAuthenticationProvider) 2개 이상
//        AuthenticationManagerBuilder authenticationManagerBuilder = http.getSharedObject(AuthenticationManagerBuilder.class);
//        authenticationManagerBuilder.authenticationProvider(authenticationProvider1()); //자식측에 customizd provider를 하나 더 추가
//        authenticationManagerBuilder.authenticationProvider(authenticationProvider2());
//
//        http
//                .authorizeRequests(auth -> auth
//                        .requestMatchers("/").permitAll()
//                        .anyRequest().authenticated())
//                .formLogin(Customizer.withDefaults())
//        ;
//
//        return http.build();
//    }

    //way2
//    @Bean
//    public AuthenticationProvider authenticationProvider() {
//        return new CustomAuthenticationProvider();
//    }

    //way3(빈객체 2개이상)
//    @Bean
//    public AuthenticationProvider authenticationProvider1() {
//        return new CustomAuthenticationProvider();
//    }
//
//    @Bean
//    public AuthenticationProvider authenticationProvider2() {
//        return new CustomAuthenticationProvider();
//    }

    //formLogin
//    @Bean
//    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//        http
//                .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
//                //.formLogin(Customizer.withDefaults());  //client 요청에 대해 기본 인증방식으로 formLogin 방식을 설정
//                .formLogin(form -> form
//                        .loginPage("/loginPage")
//                        .loginProcessingUrl("/loginProc")
//                        .defaultSuccessUrl("/", false)
//                        .failureUrl("/failed")
//                        .usernameParameter("username")
//                        .passwordParameter("password")
//                        .successHandler((request, response, authentication) -> {
//                            System.out.println("authentication success : " + authentication);
//                            response.sendRedirect("/home");
//                        })
//                        .failureHandler((request, response, exception) -> {
//                            System.out.println("authentication failure : " + exception);
//                            response.sendRedirect("/login");
//                        })
//                        .permitAll()
//                );
//
//        return http.build();
//    }

    //httpBasic
//    @Bean
//    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//        http
//                .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
//                .httpBasic(Customizer.withDefaults());
//
//        return http.build();
//    }

    //httpBasic - customized
//    @Bean
//    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//        http
//                .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
//                .httpBasic(basic ->
//                        //인증실패시
//                        basic.authenticationEntryPoint(new CustomAuthenticationEntryPoint()));
//
//        return http.build();
//    }

    //formLogin + rememberMe
//    @Bean
//    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//        http
//                .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
//                .formLogin(Customizer.withDefaults())  //client 요청에 대해 기본 인증방식으로 formLogin 방식을 설정
//                .rememberMe(rememberMe ->
//                    rememberMe
//                            .alwaysRemember(true)
//                            .tokenValiditySeconds(3600)
//                            .userDetailsService(userDetailsService())
//                            //.rememberMeServices(rememberMeServices(userDetailsService()))
//                            .rememberMeParameter("remember")
//                            //.rememberMeCookieDomain("remember")
//                            .key("security")
//                )
//        ;
//
//        return http.build();
//    }

    //anonymous
//    @Bean
//    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//        http
//                .authorizeHttpRequests(authorizeRequests ->
//                        //authorizeRequests.anyRequest().authenticated()      //모든 요청은 인증을 필요로 한다.
//                        authorizeRequests
//                                .requestMatchers("/anonymous").hasRole("GUEST") //이 URL은 GUEST 역할이 필요하다.(role - guest = role_guest)
//                                .requestMatchers("/anonymousContext", "/authentication").permitAll() //이 URL은 모든 사용자가 접근 가능하다.
//                                .anyRequest().authenticated() //이외 나머지 요청은 인증이 필요하다.
//                            )
//                .formLogin(Customizer.withDefaults())
//                /*
//                * 인증되지 않은 사용자가 접근하면 SecurityContext에 익명 Authentication을 넣어라
//                * */
//                .anonymous(anonymous
//                        -> anonymous
//                        .principal("guest")
//                        .authorities("ROLE_GUEST") //prefix
//                );
//
//        return http.build();
//    }

    //logout
//    @Bean
//    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//        http
//                .authorizeRequests(auth -> auth
//                        .requestMatchers("/logoutSuccess").permitAll()
//                        .anyRequest().authenticated())
//                //.csrf(csrf->csrf.disable()) csrf 기능 비활성화
//                .formLogin(Customizer.withDefaults())
//                .logout(logout -> logout
//                        //.logoutUrl("/logout")
//                        //.logoutRequestMatcher(new AntPathRequestMatcher("/logoutProc", "POST")) //우선 적용
//                        .logoutSuccessUrl("/logoutSuccess")
//                        .logoutSuccessHandler((req, res, aut) -> {
//                            //onLogoutSuccess
//                            res.sendRedirect("/logoutSuccess"); //우선 적용
//                        })
//                        .deleteCookies("JSESSIONID", "remember-me")
//                        .invalidateHttpSession(true) //http session
//                        .clearAuthentication(true) //security context
//                        .addLogoutHandler((req, res, aut)-> {
//                            HttpSession session = req.getSession();
//                            session.invalidate();
//                            SecurityContextHolder.getContextHolderStrategy().getContext().setAuthentication(null);
//                            SecurityContextHolder.getContextHolderStrategy().clearContext();
//                        })
//                        .permitAll()
//                );
//
//        return http.build();
//    }

//    @Bean
//    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//        //RequestCache / savedRequest는 Spring Security에 의해 자동 활용됨
//        HttpSessionRequestCache requestCache = new HttpSessionRequestCache();
//        requestCache.setMatchingRequestParameterName("customParam=y");  //이 쿼리스트링이 인증 성공 시 붙게된다.
//        http
//                .authorizeRequests(auth -> auth
//                        .requestMatchers("/logoutSuccess").permitAll()
//                        .anyRequest().authenticated()
//                )
//                //.formLogin(Customizer.withDefaults())
//                .formLogin(form -> form
//                        .successHandler((request, response, authentication) -> {
//                            SavedRequest savedRequest = requestCache.getRequest(request, response);
//                            String redirectUrl = savedRequest.getRedirectUrl();
//                            response.sendRedirect(redirectUrl);
//                            /*
//                            * 인증성공 시 ?continue..
//                            * 이것을 requestCache에서 설정한 쿼리스트링으로 변경 가능
//                            * */
//                        })
//                )
//                //request cache 정보를 그대로 반영해주어야 한다.
//                .requestCache(cache -> cache.requestCache(requestCache))
//        ;
//
//        return http.build();
//    }

    @Bean
    public UserDetailsService userDetailsService() {
//        UserDetails user = User.withUsername("user")
//                .password("{noop}1111")
//                .roles("USER")    //여기까지 다중 사용자 설정 가능
//                .build();

        return new CustomizedUserDetailService();
    }

//    @Bean
//    public RememberMeServices rememberMeServices(UserDetailsService userDetailsService) {
//        TokenBasedRememberMeServices services =
//                new TokenBasedRememberMeServices("security", userDetailsService);
//        services.setCookieName("remember");
//        services.setTokenValiditySeconds(3600);
//        return services;
//    }

}
