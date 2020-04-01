package com.cybr406.account.configuration;

import org.springframework.http.HttpMethod;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;

import javax.sql.DataSource;

@Configuration
public class SecurityConfiguration extends WebSecurityConfigurerAdapter
	{
	
		@Autowired
		DataSource dataSource;
	
		
		@Autowired
	public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception
			{
				auth.jdbcAuthentication().dataSource(dataSource);
			}
	
	@Override
	protected void configure(HttpSecurity http) throws Exception
		{
			/**
			 * Problem 07: disable sessions
			 *
			 * Session tracking via cookies is what makes a CSRF attack possible in the first place. Disabling sessions
			 * in our security settings can help mitigate the problem.
			 *
			 * Inside configure(HttpSecurity http) you need to add:
			 *     .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
			 */
			
				
			
			http.authorizeRequests()
					.mvcMatchers(HttpMethod.GET, "/", "/**").permitAll()
					.mvcMatchers(HttpMethod.POST, "/signup").permitAll()
					.anyRequest().authenticated()
					.and()
					.csrf().disable()
					.httpBasic()
					.and()
					.sessionManagement()
					.sessionCreationPolicy(SessionCreationPolicy.STATELESS);
		}
	
	}
