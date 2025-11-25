package spring_security.customized;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import spring_security.valueObject.UserInfo;

import java.util.List;

//UserDetailService 빈 객체는 CustomizedUserDetailService를 주입해준다.
public class CustomizedUserDetailService implements UserDetailsService {
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
//        UserDetails user = User.withUsername("user")
//                .password("{noop}1111")
//                .roles("USER")    //여기까지 다중 사용자 설정 가능
//                .build();
//
//        return user;
        UserInfo userinfo
                = new UserInfo("user", "{noop}1111", List.of(new SimpleGrantedAuthority("ROLE_USER")));

        return new CustomizedUserDetails(userinfo);
    }
}
