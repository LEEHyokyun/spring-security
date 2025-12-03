package spring_security.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class CsrfCookieFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        CsrfToken csrfToken = (CsrfToken) request.getAttribute("_csrf");

        if(csrfToken != null){
            //csrfToken을 html에 렌더링
            csrfToken.getToken();
            /*
            * 여기서 추출한 csrfToken은 csrf.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()) 설정에 의해
            * html에서 이를 렌더링하여 보여줄 수 있다.
            * */
        }

        filterChain.doFilter(request, response);
    }
}
