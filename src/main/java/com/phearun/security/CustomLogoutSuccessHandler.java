package com.phearun.security;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.web.authentication.AbstractAuthenticationTargetUrlRequestHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.stereotype.Component;


/**
 * Spring Security logout handler
 */
@Component
public class CustomLogoutSuccessHandler extends AbstractAuthenticationTargetUrlRequestHandler implements LogoutSuccessHandler {
	
	private final Logger log = LoggerFactory.getLogger(this.getClass());

	@Value("${app.authentication.tokenType}")
    private String TOKEN_TYPE;
	
	@Value("${app.authentication.header}")
    private String AUTH_HEADER;

    @Autowired
    private TokenStore tokenStore;

    @Override
    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
    	
        String token = request.getHeader(AUTH_HEADER);
        log.info("Token: {}", token);
        
        if (token != null && token.startsWith(TOKEN_TYPE)) {
            OAuth2AccessToken oAuth2AccessToken = tokenStore.readAccessToken(token.split(" ")[1]);
            
            if (oAuth2AccessToken != null) {
            	
                tokenStore.removeAccessToken(oAuth2AccessToken);
                log.info("Token {} removed!", token.split(" ")[1]);
                response.setStatus(HttpServletResponse.SC_OK);
                response.flushBuffer();
            }
        }
        response.setStatus(HttpServletResponse.SC_NOT_FOUND);
    }

}
