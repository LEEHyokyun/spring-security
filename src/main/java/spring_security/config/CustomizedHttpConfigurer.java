package spring_security.config;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

public class CustomizedHttpConfigurer extends AbstractHttpConfigurer<CustomizedHttpConfigurer, HttpSecurity> {

    private boolean flag;

    @Override
    public void init(HttpSecurity http) throws Exception {
        super.init(http);
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
        AuthenticationManager authenticationManager = http.getSharedObject(AuthenticationManager.class);

        CustomizedFilter customizedFilter = new CustomizedFilter();
        customizedFilter.setFlag(flag);
        http.addFilterBefore(customizedFilter, UsernamePasswordAuthenticationFilter.class);
    }

    public boolean setFlag(boolean value){
        return value;
    }

    public static CustomizedHttpConfigurer create(){
        return new  CustomizedHttpConfigurer();
    }
}
