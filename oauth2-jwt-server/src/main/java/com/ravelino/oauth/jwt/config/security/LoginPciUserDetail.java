package com.ravelino.oauth.jwt.config.security;

import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

public class LoginPciUserDetail implements UserDetailsService {

	private static final String PARAM_PASSWORD = "password";
	
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		//List<GrantedAuthority> listGrantAuthority = new ArrayList<GrantedAuthority>();
		//listGrantAuthority.add(new SimpleGrantedAuthority("USER"));
		//User user = userServiceImpl.getByEmail(email);
		//checkGrantAuthorities(user, listGrantAuthority);
		//UserDetails userDetails = validateUser(email, listGrantAuthority,user);
		return new User(username, getEncryptedPassword(), AuthorityUtils.createAuthorityList("ROLE_USER", "ROLE_ADMIN"));
		//return null;
	}
	
	private String getEncryptedPassword() {
		var request = ((ServletRequestAttributes) RequestContextHolder.getRequestAttributes()).getRequest();
		var password = request.getParameter(PARAM_PASSWORD);
		return new BCryptPasswordEncoder().encode(password);
	}

}
