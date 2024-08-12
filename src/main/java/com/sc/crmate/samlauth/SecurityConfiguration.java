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

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.session.DefaultCookieSerializerCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.saml2.provider.service.authentication.AbstractSaml2AuthenticationRequest;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
import org.springframework.security.saml2.provider.service.metadata.OpenSamlMetadataResolver;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.web.*;
import org.springframework.security.saml2.provider.service.web.authentication.Saml2AuthenticationRequestResolver;
import org.springframework.security.saml2.provider.service.web.authentication.Saml2WebSsoAuthenticationFilter;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.HeaderWriterLogoutHandler;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.authentication.www.BasicAuthenticationConverter;
import org.springframework.security.web.header.writers.ClearSiteDataHeaderWriter;
import org.springframework.util.StringUtils;
import org.springframework.security.core.AuthenticationException;
import java.io.IOException;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration {
//
//	public static Converter<OpenSaml4AuthenticationProvider.ResponseToken, Saml2ResponseValidatorResult> createDefaultResponseValidator() {
//		return (responseToken) -> {
//			Response response = responseToken.getResponse();
//			Saml2AuthenticationToken token = responseToken.getToken();
//			Saml2ResponseValidatorResult result = Saml2ResponseValidatorResult.success();
//			String statusCode = getStatusCode(response);
//			if (!StatusCode.SUCCESS.equals(statusCode)) {
//				String message = String.format("Invalid status [%s] for SAML response [%s]", statusCode,
//						response.getID());
//				result = result.concat(new Saml2Error(Saml2ErrorCodes.INVALID_RESPONSE, message));
//			}
//
//			String inResponseTo = response.getInResponseTo();
//			result = result.concat(validateInResponseTo(token.getAuthenticationRequest(), inResponseTo));
//
//			String issuer = response.getIssuer().getValue();
//			String destination = response.getDestination();
//			String location = token.getRelyingPartyRegistration().getAssertionConsumerServiceLocation();
//			if (StringUtils.hasText(destination) && !destination.equals(location)) {
//				String message = "Invalid destination [" + destination + "] for SAML response [" + response.getID()
//						+ "]";
//				result = result.concat(new Saml2Error(Saml2ErrorCodes.INVALID_DESTINATION, message));
//			}
//			String assertingPartyEntityId = token.getRelyingPartyRegistration()
//					.getAssertingPartyDetails()
//					.getEntityId();
//			if (!StringUtils.hasText(issuer) || !issuer.equals(assertingPartyEntityId)) {
//				String message = String.format("Invalid issuer [%s] for SAML response [%s]", issuer, response.getID());
//				result = result.concat(new Saml2Error(Saml2ErrorCodes.INVALID_ISSUER, message));
//			}
//			if (response.getAssertions().isEmpty()) {
//				result = result.concat(
//						new Saml2Error(Saml2ErrorCodes.MALFORMED_RESPONSE_DATA, "No assertions found in response."));
//			}
//			return result;
//		};
//	}


	@Bean
	SecurityFilterChain securityFilterChain(HttpSecurity http,
											RelyingPartyRegistrationRepository relyingPartyRegistrationRepository) throws Exception {
		RelyingPartyRegistrationResolver relyingPartyRegistrationResolver = new DefaultRelyingPartyRegistrationResolver(
				relyingPartyRegistrationRepository);
		Saml2MetadataFilter metadataFilter = new Saml2MetadataFilter(relyingPartyRegistrationResolver,
				new OpenSamlMetadataResolver());
		SecurityContextLogoutHandler securityContextLogoutHandler = new SecurityContextLogoutHandler();
		Saml2AuthenticationRequestResolver authenticationRequestResolver;

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
				//testuser2@spring.security.saml
//				.saml2Login(
//						login -> {
//					login.successHandler(new CustomSuccessHandler());
//					login.failureHandler(new CustomFailureHandler("/?continue"));
//					login.authenticationConverter(new CustomBasicAuthenticationConverter(relyingPartyRegistrationResolver));
//					login.authenticationRequestResolver(new CustomAuthenticationRequestResolver(relyingPartyRegistrationRepository));
//				}
//				)
				.saml2Login(Customizer.withDefaults())
				.saml2Logout(Customizer.withDefaults())
				.addFilterBefore(metadataFilter, Saml2WebSsoAuthenticationFilter.class);
		// @formatter:on
		return http.build();
	}

	private class CustomSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {
		@Override
		public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws ServletException, IOException {
			String targetUrlParameter = this.getTargetUrlParameter();
			if (!this.isAlwaysUseDefaultTargetUrl() && (targetUrlParameter == null || !StringUtils.hasText(request.getParameter(targetUrlParameter)))) {
				this.clearAuthenticationAttributes(request);
				String targetUrl = "/";
				this.getRedirectStrategy().sendRedirect(request, response, targetUrl);
			} else {
				super.onAuthenticationSuccess(request, response, authentication);
			}
		}

	}


	private class CustomFailureHandler implements AuthenticationFailureHandler {

		@Autowired
		private Saml2AuthenticatedPrincipal principal;
		private String samlFailureCallbackURL;

		private RedirectStrategy redirectStragegy = new DefaultRedirectStrategy();

		public CustomFailureHandler(String samlFailureCallbackURL) {
			System.out.println("Handling SAML Auth Failure");
			this.samlFailureCallbackURL = samlFailureCallbackURL;
		}
		@Override
		public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
			System.out.println("Exception " + exception.getMessage());
			this.redirectStragegy.sendRedirect(request, response, this.samlFailureCallbackURL);
		}
	}



	//	@Bean
//	public DefaultCookieSerializerCustomizer cookieSerializerCustomizer() {
//
//		return cookieSerializer -> {
//			// Default of sameSite = "Lax" breaks SAML; setting to None with secure cookies here
//			cookieSerializer.setSameSite("None");
//			cookieSerializer.setUseSecureCookie(true);
//		};
//	}
	HttpSessionSaml2AuthenticationRequestRepository req;




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