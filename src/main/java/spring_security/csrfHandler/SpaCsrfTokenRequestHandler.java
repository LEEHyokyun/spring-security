package spring_security.csrfHandler;

import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.security.web.csrf.XorCsrfTokenRequestAttributeHandler;
import org.springframework.security.web.server.csrf.XorServerCsrfTokenRequestAttributeHandler;
import org.springframework.util.StringUtils;

import java.util.function.Supplier;

public class SpaCsrfTokenRequestHandler extends CsrfTokenRequestAttributeHandler {

    //XOR - 토큰의 처리
    //CsrfTokenRequestAttributeHandler - 토큰의 디코딩
    private final CsrfTokenRequestAttributeHandler csrfTokenRequestAttributeHandler = new XorCsrfTokenRequestAttributeHandler();

    //csrfToken 처리 = handler에게 그대로 위임
    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, Supplier<CsrfToken> deferredCsrfToken){
        csrfTokenRequestAttributeHandler.handle(request, response, deferredCsrfToken);
    }

    @Override
    public String resolveCsrfTokenValue(HttpServletRequest request, CsrfToken csrfToken){
        if(StringUtils.hasText(request.getHeader(csrfToken.getHeaderName()))){
            //헤더가 있으면 인코딩된 csrf 토큰이므로 디코딩 필요
            return super.resolveCsrfTokenValue(request, csrfToken);
        }

        return csrfTokenRequestAttributeHandler.resolveCsrfTokenValue(request, csrfToken);
    }

}
