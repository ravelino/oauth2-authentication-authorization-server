package com.ravelino.oauth.jwt.config.security;

import java.security.KeyPair;
import java.time.Duration;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenEnhancerChain;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;

import com.ravelino.oauth.jwt.config.props.SecurityProperties;

@Configuration
@EnableAuthorizationServer
@EnableConfigurationProperties(SecurityProperties.class)
public class AuthorizationServerConfiguration extends AuthorizationServerConfigurerAdapter {

	@Autowired
    private PasswordEncoder passwordEncoder;
	
	@Autowired
    private AuthenticationManager authenticationManager;
    
	@Autowired
	private SecurityProperties securityProperties;
	
	@Value("${security.oauth2.client}")
	private String client;
	
	@Value("${security.oauth2.secret}")
	private String secret;
    
	private JwtAccessTokenConverter jwtAccessTokenConverter;
    
	private TokenStore tokenStore;
	

    @Override
    public void configure(final ClientDetailsServiceConfigurer clients) throws Exception {
    	BCryptPasswordEncoder bcryptEncode = new BCryptPasswordEncoder();
    	
    	clients.inMemory()
	        .withClient(client)
	        .secret(bcryptEncode.encode(secret))
	        .authorizedGrantTypes("refresh_token", "password", "client_credentials")
	        .scopes("read")
	        .scopes("write")
	        .accessTokenValiditySeconds(Duration.ofMinutes(60).toSecondsPart());
    }
    
    @Override
    public void configure(final AuthorizationServerEndpointsConfigurer endpoints) {
    	
    	final var tokenConverter = jwtAccessTokenConverter();
    	
    	final var tokenEnhancerChain = new TokenEnhancerChain();
        tokenEnhancerChain.setTokenEnhancers(List.of(loginPciTokenEnhancer(), tokenConverter));
    	
        endpoints.authenticationManager(this.authenticationManager)
        		.tokenEnhancer(tokenEnhancerChain)
                .accessTokenConverter(tokenConverter)
                .tokenStore(tokenStore());
    }
    
    @Override
    public void configure(final AuthorizationServerSecurityConfigurer oauthServer) {
        oauthServer
        	.passwordEncoder(this.passwordEncoder)
        	.tokenKeyAccess("permitAll()")
            .checkTokenAccess("isAuthenticated()");
    }

    @Bean
    public TokenStore tokenStore() {
        if (tokenStore == null) {
            tokenStore = new JwtTokenStore(jwtAccessTokenConverter());
        }
        return tokenStore;
    }

    @Bean
    public DefaultTokenServices tokenServices(final TokenStore tokenStore,
                                              final ClientDetailsService clientDetailsService) {
        final var tokenServices = new DefaultTokenServices();
        tokenServices.setSupportRefreshToken(true);
        tokenServices.setTokenStore(tokenStore);
        tokenServices.setClientDetailsService(clientDetailsService);
        tokenServices.setAuthenticationManager(this.authenticationManager);
        return tokenServices;
    }

    @Bean
    public JwtAccessTokenConverter jwtAccessTokenConverter() {
        if (jwtAccessTokenConverter != null) {
            return jwtAccessTokenConverter;
        }

        final var jwtProperties = securityProperties.getJwt();
        final var keyPair = keyPair(jwtProperties, keyStoreKeyFactory(jwtProperties));

        jwtAccessTokenConverter = new JwtAccessTokenConverter();
        jwtAccessTokenConverter.setKeyPair(keyPair);
        return jwtAccessTokenConverter;
    }

    @Bean
    public LoginPciTokenEnhancer loginPciTokenEnhancer() {
    	return new LoginPciTokenEnhancer();
    }

    private KeyPair keyPair(SecurityProperties.JwtProperties jwtProperties, KeyStoreKeyFactory keyStoreKeyFactory) {
        return keyStoreKeyFactory
        			.getKeyPair(
						jwtProperties.getKeyPairAlias(),
						jwtProperties.getKeyPairPassword().toCharArray()
					);
    }

    private KeyStoreKeyFactory keyStoreKeyFactory(SecurityProperties.JwtProperties jwtProperties) {
        return new KeyStoreKeyFactory(
										jwtProperties.getKeyStore(),
										jwtProperties.getKeyStorePassword().toCharArray()
									);
    }
}
