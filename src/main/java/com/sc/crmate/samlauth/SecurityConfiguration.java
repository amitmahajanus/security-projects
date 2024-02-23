/*
 * Copyright 2002-2022 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.sc.crmate.samlauth;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.opensaml.saml.saml2.wssecurity.messaging.impl.DefaultSAML20AssertionValidationContextBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.saml2.provider.service.metadata.OpenSamlMetadataResolver;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.web.DefaultRelyingPartyRegistrationResolver;
import org.springframework.security.saml2.provider.service.web.RelyingPartyRegistrationResolver;
import org.springframework.security.saml2.provider.service.web.Saml2MetadataFilter;
import org.springframework.security.saml2.provider.service.web.authentication.Saml2WebSsoAuthenticationFilter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.CookieClearingLogoutHandler;
import org.springframework.security.web.authentication.logout.HeaderWriterLogoutHandler;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestHandler;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
import org.springframework.security.web.header.writers.ClearSiteDataHeaderWriter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.function.Supplier;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration {

	@Bean
	SecurityFilterChain securityFilterChain(HttpSecurity http,
											RelyingPartyRegistrationRepository relyingPartyRegistrationRepository) throws Exception {
		RelyingPartyRegistrationResolver relyingPartyRegistrationResolver = new DefaultRelyingPartyRegistrationResolver(
				relyingPartyRegistrationRepository);
		Saml2MetadataFilter metadataFilter = new Saml2MetadataFilter(relyingPartyRegistrationResolver,
				new OpenSamlMetadataResolver());
		SecurityContextLogoutHandler securityContextLogoutHandler = new SecurityContextLogoutHandler();


		HeaderWriterLogoutHandler clearSiteData = new HeaderWriterLogoutHandler(new ClearSiteDataHeaderWriter(ClearSiteDataHeaderWriter.Directive.ALL));
		// @formatter:off
		http
				.authorizeHttpRequests((authorize) -> authorize
						.requestMatchers("/error", "/welcome", "/csrf", "/email").permitAll()
						.anyRequest().authenticated()
				)
				.csrf(c -> {
					c.disable();
				})
				.cors(cors -> {
					cors.disable();
				})
				.logout(logout -> {
//					logout.invalidateHttpSession(true);
//					logout.logoutRequestMatcher(new AntPathRequestMatcher("/logout"));
					logout.clearAuthentication(true);

//					logout.addLogoutHandler(clearSiteData);
					logout.deleteCookies("JSESSIONID");
//					logout.addLogoutHandler((request, response, auth) -> {
//						for (Cookie cookie : request.getCookies()) {
//							String cookieName = cookie.getName();
//							Cookie cookieToDelete = new Cookie(cookieName, null);
//							cookieToDelete.setMaxAge(0);
//							response.addCookie(cookieToDelete);
//						}
//					});
					logout.addLogoutHandler(new SecurityContextLogoutHandler());
//					logout.addLogoutHandler(securityContextLogoutHandler);
//					logout.addLogoutHandler(new CookieClearingLogoutHandler("JSESSIONID"));
					logout.logoutSuccessUrl("/welcome");
				})
				.exceptionHandling(exception -> {
					exception.accessDeniedPage("/index");
				})
				.saml2Login(Customizer.withDefaults())
				.saml2Logout(Customizer.withDefaults())
				.addFilterBefore(metadataFilter, Saml2WebSsoAuthenticationFilter.class);
		// @formatter:on
		return http.build();
	}


/*	@Bean
	public CorsConfigurationSource corsConfigurationSource() {
		CorsConfiguration configuration = new CorsConfiguration();
		configuration.setAllowedOrigins(Arrays.asList("*","http://localhost:3000", "http://localhost:3000/api"));
		configuration.setAllowedMethods(Arrays.asList("HEAD", "GET", "PUT", "POST", "DELETE", "PATCH"));
		configuration.setAllowCredentials(true);
		//the below three lines will add the relevant CORS response headers
		configuration.addAllowedOrigin("*");
		configuration.addAllowedHeader("*");
		configuration.addAllowedMethod("*");
		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/**", configuration);
		return source;
	}*/


}