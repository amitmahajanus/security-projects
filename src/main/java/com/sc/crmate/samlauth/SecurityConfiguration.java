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

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.saml2.provider.service.metadata.OpenSamlMetadataResolver;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.web.DefaultRelyingPartyRegistrationResolver;
import org.springframework.security.saml2.provider.service.web.RelyingPartyRegistrationResolver;
import org.springframework.security.saml2.provider.service.web.Saml2MetadataFilter;
import org.springframework.security.saml2.provider.service.web.authentication.Saml2WebSsoAuthenticationFilter;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration {

	@Bean
	SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		OpenSaml4AuthenticationProvider authenticationProvider = new OpenSaml4AuthenticationProvider();
		authenticationProvider.setResponseAuthenticationConverter((responseToken)->{
			Saml2Authentication authentication = OpenSaml4AuthenticationProvider.createDefaultResponseAuthenticationConverter()
					.convert(responseToken);
			return processSaml2Authentication(responseToken,authentication);
		});

		// @formatter:off
		http
				.authorizeHttpRequests((authorize) -> authorize
						.requestMatchers("/error").permitAll()
						.anyRequest().authenticated()
				)
				.saml2Login((saml2) -> saml2.relyingPartyRegistrationRepository(relyingPartyRegistrations()))
				.saml2Logout(Customizer.withDefaults())
				.saml2Metadata(Customizer.withDefaults());
		// @formatter:on
		return http.build();
	}

	private AbstractAuthenticationToken processSaml2Authentication(OpenSaml4AuthenticationProvider.ResponseToken responseToken, Saml2Authentication authentication) {

		return responseToken.getToken();
	}

	private RelyingPartyRegistrationRepository relyingPartyRegistrations() {
		RelyingPartyRegistration registration = RelyingPartyRegistrations.fromMetadataLocation("http://localhost:9090/openam/saml2/jsp/exportmetadata.jsp")
				.assertingPartyDetails((party)->
				{
					party.singleSignOnServiceBinding(Saml2MessageBinding.POST);
				})
				.assertionConsumerServiceBinding(Saml2MessageBinding.POST)
				.registrationId("one")
				.build();
		return new InMemoryRelyingPartyRegistrationRepository(registration);
	}

	@Bean
	Saml2AuthenticationRequestResolver authenticationRequestResolver(RelyingPartyRegistrationRepository registrations) {

		RelyingPartyRegistration registration = RelyingPartyRegistrations.fromMetadataLocation("http://localhost:9090/openam/saml2/jsp/exportmetadata.jsp")
				.assertingPartyDetails((party)->
				{
					party.singleSignOnServiceBinding(Saml2MessageBinding.POST);
				})
				.assertionConsumerServiceBinding(Saml2MessageBinding.POST)
				.registrationId("one")
				.build();
		RelyingPartyRegistrationRepository relyingPartyRegistrationRepository = new InMemoryRelyingPartyRegistrationRepository(registration);
		OpenSaml4AuthenticationRequestResolver authenticationRequestResolver =
				new OpenSaml4AuthenticationRequestResolver(relyingPartyRegistrationRepository);
		authenticationRequestResolver.setAuthnRequestCustomizer((context) -> {
			context.getAuthnRequest().getIssuer().setValue("https://localhost:8080/newIssuer");
			context.getAuthnRequest().setAssertionConsumerServiceURL("https://localhost:8080/newACS");
		});
		return authenticationRequestResolver;
	}
}
