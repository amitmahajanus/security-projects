/*
 * Copyright 2020 the original author or authors.
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
import jakarta.servlet.http.HttpSession;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
import org.springframework.security.web.authentication.logout.CookieClearingLogoutHandler;
import org.springframework.security.web.authentication.logout.HeaderWriterLogoutHandler;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
import org.springframework.security.web.header.writers.ClearSiteDataHeaderWriter;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.Arrays;
import java.util.Enumeration;

@Controller
public class IndexController {

	@GetMapping("/")
	@ResponseBody
	public String index(Model model, @AuthenticationPrincipal Saml2AuthenticatedPrincipal principal,
						HttpServletRequest request,
						HttpServletResponse response,
						HttpSession httpSession,
						CsrfToken csrfToken) {
		String emailAddress = principal.getFirstAttribute("email");
		System.out.println("CSRF Token Values is: " + request.getSession().getAttribute("SPRING_SECURITY_CONTEXT"));
		Enumeration<String> attributes = request.getSession(false).getAttributeNames();
		while(attributes.hasMoreElements()) {
			String s = attributes.nextElement();
			System.out.println("Session attribute " + s);
		}

//		System.out.println("Security token " + csrfToken.getToken());
		model.addAttribute("emailAddress", request.getSession().getAttribute("HttpSessionCsrfTokenRepository.CSRF_TOKEN"));
		model.addAttribute("userAttributes", principal.getAttributes());
		httpSession.setAttribute("emailAddress", emailAddress);
		httpSession.setAttribute("attributes", principal.getAttributes());
		return emailAddress;
//		return "redirect:http://localhost:3000/index";
	}

	@GetMapping("/welcome")
	public String welcome() {
		return "welcome";
	}

	@GetMapping("my-logout")
	public String performLogout(Authentication authentication, HttpServletRequest request, HttpServletResponse response) {

		SecurityContextLogoutHandler logoutHandler = new SecurityContextLogoutHandler();
		HeaderWriterLogoutHandler clearSiteData = new HeaderWriterLogoutHandler(new ClearSiteDataHeaderWriter(ClearSiteDataHeaderWriter.Directive.COOKIES));
		CookieClearingLogoutHandler cookieClearingLogoutHandler = new CookieClearingLogoutHandler("JSESSIONID");
		cookieClearingLogoutHandler.logout(request, response, authentication);
		SecurityContextLogoutHandler securityContextLogoutHandler = new SecurityContextLogoutHandler();
		securityContextLogoutHandler.logout(request, response, authentication);
//		request.getSession(false).removeAttribute("SPRING_SECURITY_CONTEXT");
		clearSiteData.logout(request, response, authentication);
		logoutHandler.logout(request, response, authentication);

		return "mylogout";
	}
	@GetMapping("/logout/saml2/slo/one")
	public String customLogout(Authentication authentication, HttpServletRequest request, HttpServletResponse response) {

		return "mylogout";
	}


	@GetMapping("/email")
	@ResponseBody
	@CrossOrigin(originPatterns = "http://localhost:3000/*" , allowCredentials = "true" , exposedHeaders = {"Access-Control-Allow-Origin","Access-Control-Allow-Credentials"})
	public String getEmail(HttpSession httpSession) {
		return (String) httpSession.getAttribute("emailAddress");
	}
}
