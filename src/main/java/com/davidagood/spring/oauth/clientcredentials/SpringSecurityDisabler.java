package com.davidagood.spring.oauth.clientcredentials;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
class SpringSecurityDisabler {

	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		// Do nothing
		http.authorizeHttpRequests((authz) -> authz.anyRequest().permitAll());
		return http.build();
	}

}
