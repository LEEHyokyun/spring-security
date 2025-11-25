package spring_security.customized;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

//UserDetailService 빈 객체는 CustomizedUserDetailService를 주입해준다.
public class CustomizedUserDetailService implements UserDetailsService {
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserDetails user = User.withUsername("user")
                .password("{noop}1111")
                .roles("USER")    //여기까지 다중 사용자 설정 가능
                .build();

        return user;
    }
}
