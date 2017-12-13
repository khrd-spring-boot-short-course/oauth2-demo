package com.phearun.configuration;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JdbcTokenStore;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import com.phearun.security.CustomAuthenticationEntryPoint;
import com.phearun.security.CustomLogoutSuccessHandler;

@Configuration
public class OAuth2Configuration {

    @Configuration
    @EnableResourceServer
    protected static class ResourceServerConfiguration extends ResourceServerConfigurerAdapter {
    	
        @Autowired
        private CustomAuthenticationEntryPoint customAuthenticationEntryPoint;

        @Autowired
        private CustomLogoutSuccessHandler customLogoutSuccessHandler;

        @Override
        public void configure(HttpSecurity http) throws Exception {

            http
            	.exceptionHandling()
                	.authenticationEntryPoint(customAuthenticationEntryPoint)
                .and()
                    .logout()
                    .logoutUrl("/oauth/logout")
                    .logoutSuccessHandler(customLogoutSuccessHandler)
               .and()
                    .csrf()
                    .requireCsrfProtectionMatcher(new AntPathRequestMatcher("/oauth/authorize")).disable()
               .headers()
                    .frameOptions().disable() 
               .and()
               		.sessionManagement()
               			.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
               .and()
                    .authorizeRequests()
                    //.antMatchers("/hello/").permitAll()
                    .antMatchers("/secure/**").authenticated()
               ;
        }

    }

    @Configuration
    @EnableAuthorizationServer
    protected static class AuthorizationServerConfiguration extends AuthorizationServerConfigurerAdapter {
    	
        @Autowired
        private DataSource dataSource;

        @Autowired
        @Qualifier("authenticationManagerBean")
        private AuthenticationManager authenticationManager;

        @Override
        public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
            endpoints
                    .tokenStore(tokenStore())
                    .authenticationManager(authenticationManager);
        }
        
      
        //TODO: Client Detail
        //-> InMemory Client
        @Override
        public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
            clients
                    .inMemory()
                    .withClient("trusted-client")
                    .scopes("read", "write", "trust")
                    .authorities("ROLE_ADMIN", "ROLE_USER")
                    .authorizedGrantTypes("password", "refresh_token", "client_credentials")
                    .secret("secret")
                    .accessTokenValiditySeconds(30)
                    .refreshTokenValiditySeconds(15*60)
                    ;
        }
        
        //-> JDBC Client
        /*@Override
        public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        	clients.jdbc(dataSource);
        }*/
        
        //-> ClientDetailService Client
        
        //TODO: Token Store
        /*@Bean
        public TokenStore tokenStore() {
            return new InMemoryTokenStore();
        }*/
        
        @Bean
        public TokenStore tokenStore() {
            return new JdbcTokenStore(dataSource);
        }

        /*
        //JWT TokenStore
		@Override
		public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
			TokenEnhancerChain tokenEnhancerChain = new TokenEnhancerChain();
			tokenEnhancerChain.setTokenEnhancers(Arrays.asList(accessTokenConverter()));
			
			endpoints
				.tokenStore(tokenStore()).tokenEnhancer(tokenEnhancerChain)
				.authenticationManager(authenticationManager);
		}
        
        @Bean
        @Primary
        public DefaultTokenServices tokenServices() {
            final DefaultTokenServices defaultTokenServices = new DefaultTokenServices();
            defaultTokenServices.setTokenStore(tokenStore());
            defaultTokenServices.setSupportRefreshToken(true);
            return defaultTokenServices;
        }
        
        @Bean
        public TokenStore tokenStore() {
            return new JwtTokenStore(accessTokenConverter());
        }

        @Bean
        public JwtAccessTokenConverter accessTokenConverter() {
            final JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
            converter.setSigningKey("signkey");
            return converter;
        }
        //End JWT TokenStore
		*/
    }

}
