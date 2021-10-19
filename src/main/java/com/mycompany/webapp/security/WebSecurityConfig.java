package com.mycompany.webapp.security;

import javax.annotation.Resource;
import javax.sql.DataSource;

import org.springframework.context.annotation.Bean;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.access.expression.DefaultWebSecurityExpressionHandler;

import lombok.extern.slf4j.Slf4j;

@EnableWebSecurity
@Slf4j
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
	@Resource
	private DataSource dataSource;
	@Resource
	private CustomUserDetailsService customUserDetailService;
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		log.info("configure(HttpSecurity http) 실행");
		//로그인 설정
		http.formLogin()
			.loginPage("/security/loginForm")			//default : /login (GET)
			.usernameParameter("mid")					//default : username
			.passwordParameter("mpassword")				//default : password
			.loginProcessingUrl("/login")				//default : /login
			.defaultSuccessUrl("/security/content")		
			.failureUrl("/security/loginError");		//default : /login?error
		
		//로그아웃 설정
		http.logout()
			.logoutUrl("/logout")						//default : /logout
			.logoutSuccessUrl("/security/content");		
		
		//URL 권한 설정
		http.authorizeRequests()
			.antMatchers("/security/admin/**").hasAuthority("ROLE_ADMIN")
			.antMatchers("/security/manager/**").hasAuthority("ROLE_MANAGER")
			.antMatchers("/security/user/**").authenticated()
			.antMatchers("/**").permitAll();
		
		//권한 없음일 경우(403 ERROR) 이동할 경로 설정
		http.exceptionHandling().accessDeniedPage("/security/accessDenied");
		
		//CSRF 설정
		http.csrf().disable();
	}
	
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		log.info("configure(AuthenticationManagerBuilder auth) 실행");
		//AuthenticationManagerBuilder : 아이디와 비밀번호를 비교
		//데이터 베이스에서 가져올 사용자 정보 설정
		//패스워드 인코딩 방법 설정
		/*
		auth.jdbcAuthentication()
			.dataSource(dataSource)
			.usersByUsernameQuery("SELECT mid, mpassword, menabled FROM member WHERE mid=?")
			.authoritiesByUsernameQuery("SELECT mid, mrole FROM member WHERE mid=?")
			.passwordEncoder(passwordEncoder); //default : DelegatingPasswordEncoder
		*/
		DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
		provider.setUserDetailsService(customUserDetailService);
		//provider.setPasswordEncoder(passwordEncoder()); //default: DelegatingPasswordEncoder
		auth.authenticationProvider(provider);
	}
	
	//@Bean : 메서드가 return하는 객체를 관리 객체로 만든다.
	@Bean
	public PasswordEncoder passwordEncoder() {
		PasswordEncoder passwordEncoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
		//PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
		return passwordEncoder;
	}
	
	@Resource
	private PasswordEncoder passwordEncoder;
	
	
	@Override
	public void configure(WebSecurity web) throws Exception {
		log.info("configure(WebSecurity web) 실행");
		//권한 계층 관계 설정
		DefaultWebSecurityExpressionHandler handler = new DefaultWebSecurityExpressionHandler();
		handler.setRoleHierarchy(roleHierarchyImpl());
		web.expressionHandler(handler);
		web.ignoring()
			.antMatchers("/images/**")
			.antMatchers("/css/**")
			.antMatchers("/jquery/**")
			.antMatchers("/bootstrap-4.6.0-dist/**")
			.antMatchers("/favicon.ico");
	}
	
	//SpringSecurity 내부적으로 사용되게 할 수 있게 관리 객체로 등록
	//권한 계층을 참조하기 위해 HttpSecurity에서 사용하기 때문에 관리 빈으로 반드시 등록해야함
	@Bean
	public RoleHierarchyImpl roleHierarchyImpl() {
		RoleHierarchyImpl roleHierarchyImpl = new RoleHierarchyImpl();
		roleHierarchyImpl.setHierarchy("ROLE_ADMIN > ROLE_MANAGER > ROLE_USER");
		return roleHierarchyImpl;
	}
	
	
}
