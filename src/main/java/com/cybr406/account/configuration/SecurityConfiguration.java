package com.cybr406.account.configuration;

import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.context.annotation.Configuration;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;


import javax.sql.DataSource;

@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true)

public class SecurityConfiguration extends WebSecurityConfigurerAdapter
	{
	@Value("${spring.h2.console.enabled}")
	boolean h2ConsoleEnabled;
	
	@Autowired
	DataSource dataSource;
	
	@Autowired
	H2SecurityConfigurer h2SecurityConfigurer;
	
	@Bean
	public UserDetailsManager userDetailsManager() {
		return new JdbcUserDetailsManager(dataSource);
	}
	
	@Bean
	PasswordEncoder passwordEncoder()
		{
			return PasswordEncoderFactories.createDelegatingPasswordEncoder();
		}
	
	@Bean
	User.UserBuilder userBuilder() {
		PasswordEncoder passwordEncoder = passwordEncoder();
		
		User.UserBuilder users = User.builder();
		
		users.passwordEncoder(passwordEncoder::encode);
		
		return users;
	}
	
	@Autowired
	public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception
		{
			auth.jdbcAuthentication().dataSource(dataSource);
		}
	
	
	@Override
	protected void configure(HttpSecurity HTTP) throws Exception
		{
			h2SecurityConfigurer.configure(HTTP);
			
			if (h2ConsoleEnabled) {
				HTTP.authorizeRequests()
						.antMatchers("/h2-console/**", "/h2-console").permitAll();
				
				HTTP.headers().frameOptions().sameOrigin();
			}
			
			
			/**
			 * Problem 07: disable sessions
			 *
			 * Session tracking via cookies is what makes a CSRF attack possible in the first place. Disabling sessions
			 * in our security settings can help mitigate the problem.
			 *
			 * Inside configure(HttpSecurity http) you need to add:
			 *     .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
			 */
			
			
			HTTP.authorizeRequests()
					.mvcMatchers(HttpMethod.GET, "/check-user").hasAnyRole("ADMIN", "SERVICE")
					.mvcMatchers(HttpMethod.GET , "/" , "/**").permitAll()
					.mvcMatchers(HttpMethod.POST , "/signup").permitAll()
					.anyRequest().authenticated()
					.and()
					.csrf().disable()
					.httpBasic()
					.and()
					.sessionManagement()
					.sessionCreationPolicy(SessionCreationPolicy.STATELESS);
		}
	}
