package com.sc.crmate.samlauth;

import jakarta.servlet.http.HttpServletRequest;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.saml2.provider.service.authentication.AbstractSaml2AuthenticationRequest;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.web.RelyingPartyRegistrationResolver;
import org.springframework.security.saml2.provider.service.web.authentication.Saml2AuthenticationRequestResolver;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;

import java.time.Clock;
import java.time.Instant;
import java.util.function.Consumer;

public class CustomAuthenticationRequestResolver implements Saml2AuthenticationRequestResolver {
    private final CustomSamlAuthRequestResolver authnRequestResolver;

    private Consumer<CustomAuthenticationRequestResolver.AuthnRequestContext> contextConsumer = (parameters) -> {
    };

    private Clock clock = Clock.systemUTC();

    /**
     * Construct an {@link CustomAuthenticationRequestResolver}
     * @param registrations a repository for relying and asserting party configuration
     * @since 6.1
     */
    public CustomAuthenticationRequestResolver(RelyingPartyRegistrationRepository registrations) {
        this.authnRequestResolver = new CustomSamlAuthRequestResolver((request, id) -> {
            if (id == null) {
                return null;
            }
            return registrations.findByRegistrationId(id);
        });
    }

    /**
     * Construct a {@link CustomAuthenticationRequestResolver}
     */
    public CustomAuthenticationRequestResolver(RelyingPartyRegistrationResolver relyingPartyRegistrationResolver) {
        this.authnRequestResolver = new CustomSamlAuthRequestResolver(relyingPartyRegistrationResolver);
    }

    @Override
    public <T extends AbstractSaml2AuthenticationRequest> T resolve(HttpServletRequest request) {
        return this.authnRequestResolver.resolve(request, (registration, authnRequest) -> {
            authnRequest.setIssueInstant(Instant.now(this.clock));
            this.contextConsumer.accept(new CustomAuthenticationRequestResolver.AuthnRequestContext(request, registration, authnRequest));
        });
    }

    /**
     * Set a {@link Consumer} for modifying the OpenSAML {@link AuthnRequest}
     * @param contextConsumer a consumer that accepts an {@link CustomAuthenticationRequestResolver.AuthnRequestContext}
     */
    public void setAuthnRequestCustomizer(Consumer<CustomAuthenticationRequestResolver.AuthnRequestContext> contextConsumer) {
        Assert.notNull(contextConsumer, "contextConsumer cannot be null");
        this.contextConsumer = contextConsumer;
    }

    /**
     * Set the {@link RequestMatcher} to use for setting the
     * {@link CustomAuthenticationRequestResolver#setRequestMatcher(RequestMatcher)}
     * (RequestMatcher)}
     * @param requestMatcher the {@link RequestMatcher} to identify authentication
     * requests.
     * @since 5.8
     */
    public void setRequestMatcher(RequestMatcher requestMatcher) {
        Assert.notNull(requestMatcher, "requestMatcher cannot be null");
        this.authnRequestResolver.setRequestMatcher(requestMatcher);
    }

    /**
     * Use this {@link Clock} for generating the issued {@link Instant}
     * @param clock the {@link Clock} to use
     */
    public void setClock(Clock clock) {
        Assert.notNull(clock, "clock must not be null");
        this.clock = clock;
    }

    /**
     * Use this {@link Converter} to compute the RelayState
     * @param relayStateResolver the {@link Converter} to use
     * @since 5.8
     */
    public void setRelayStateResolver(Converter<HttpServletRequest, String> relayStateResolver) {
        Assert.notNull(relayStateResolver, "relayStateResolver cannot be null");
        this.authnRequestResolver.setRelayStateResolver(relayStateResolver);
    }

    public static final class AuthnRequestContext {

        private final HttpServletRequest request;

        private final RelyingPartyRegistration registration;

        private final AuthnRequest authnRequest;

        public AuthnRequestContext(HttpServletRequest request, RelyingPartyRegistration registration,
                                   AuthnRequest authnRequest) {
            this.request = request;
            this.registration = registration;
            this.authnRequest = authnRequest;
        }

        public HttpServletRequest getRequest() {
            return this.request;
        }

        public RelyingPartyRegistration getRelyingPartyRegistration() {
            return this.registration;
        }

        public AuthnRequest getAuthnRequest() {
            return this.authnRequest;
        }

    }
}
