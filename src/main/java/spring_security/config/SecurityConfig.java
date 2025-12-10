package spring_security.config;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.aspectj.apache.bcel.classfile.Module;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.authentication.*;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.authorization.*;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.expression.DefaultHttpSecurityExpressionHandler;
import org.springframework.security.web.access.expression.DefaultWebSecurityExpressionHandler;
import org.springframework.security.web.access.expression.WebExpressionAuthorizationManager;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.rememberme.TokenBasedRememberMeServices;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.security.web.servlet.util.matcher.MvcRequestMatcher;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.AnyRequestMatcher;
import org.springframework.security.web.util.matcher.RegexRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcherEntry;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.CorsUtils;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.servlet.HandlerMapping;
import org.springframework.web.servlet.handler.HandlerMappingIntrospector;
import spring_security.event.CustomizedAuthenticationFailureEvent;
import spring_security.event.CustomizedAuthenticationSuccessEvent;
import spring_security.event.DefaultAuthenticationFailureEvent;
import spring_security.exception.CustomizedException;
import spring_security.manager.CustomizedAuthenticationProvider;
import spring_security.publisher.CustomizedAuthorizationEventPublisher;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

@EnableWebSecurity
@Configuration
@RequiredArgsConstructor
public class SecurityConfig {

    private final ApplicationContext applicationEventPublisher;

    //정적자원접근 허용
    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return web -> web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, ApplicationContext context) throws Exception {

        http
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/user").hasAuthority("ROLE_USER")
                        .requestMatchers("/db").hasAuthority("ROLE_DB")
                        .requestMatchers("/admin").hasAuthority("ROLE_ADMIN")
                        .anyRequest().authenticated() //secured/jsr보다 더 우선순위
                )
                .formLogin(form -> form.successHandler(new AuthenticationSuccessHandler() {
                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        applicationEventPublisher.publishEvent(new CustomizedAuthenticationSuccessEvent(authentication));
                        response.sendRedirect("/");
                    }
                }))
                .authenticationProvider(authenticationProvider())
                .csrf(AbstractHttpConfigurer::disable)
        ;

        return http.build();
    }

    @Bean
    AuthenticationProvider authenticationProvider() {
        return new CustomizedAuthenticationProvider(applicationEventPublisher);
    }

    @Bean
    public DefaultAuthenticationEventPublisher authenticationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {

        Map<Class<? extends AuthenticationException>, Class<? extends AbstractAuthenticationFailureEvent>> mapping =
                Collections.singletonMap(CustomizedException.class, CustomizedAuthenticationFailureEvent.class);

        DefaultAuthenticationEventPublisher authenticationEventPublisher = new DefaultAuthenticationEventPublisher(applicationEventPublisher);
        authenticationEventPublisher.setAdditionalExceptionMappings(mapping);
        authenticationEventPublisher.setDefaultAuthenticationFailureEvent(DefaultAuthenticationFailureEvent.class); //default

        return authenticationEventPublisher;
    }

    //basic
    /*@Bean
    public AuthorizationEventPublisher authorizationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
        return new SpringAuthorizationEventPublisher(applicationEventPublisher);
    }*/

    //Customized
    @Bean
    public AuthorizationEventPublisher myAuthorizationEventPublisher(ApplicationEventPublisher applicationEventPublisher){
        return new CustomizedAuthorizationEventPublisher(new SpringAuthorizationEventPublisher(applicationEventPublisher), applicationEventPublisher);
    }

    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails user = User.withUsername("user").password("{noop}1111").roles("USER").build();   //여기까지 다중 사용자 설정 가능
        UserDetails manager = User.withUsername("manager").password("{noop}1111").roles("MANAGER").build();
        UserDetails admin = User.withUsername("admin").password("{noop}1111").roles("ADMIN", "WRITE").build();

        return new InMemoryUserDetailsManager(user, manager, admin);
    }
}
