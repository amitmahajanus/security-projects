package com.sc.crmate.samlauth;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.cache.Cache;
import org.springframework.cache.concurrent.ConcurrentMapCache;
import org.springframework.security.saml2.core.Saml2ParameterNames;
import org.springframework.security.saml2.provider.service.authentication.AbstractSaml2AuthenticationRequest;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class CustomSaml2AuthenticationRequestRepositoryTest {

    private CustomSaml2AuthenticationRequestRepository repository;
    private Cache cache;
    private HttpServletRequest request;
    private HttpServletResponse response;
    private AbstractSaml2AuthenticationRequest authenticationRequest;

    @BeforeEach
    void setUp() {
        cache = new ConcurrentMapCache("samlrequests");
        repository = new CustomSaml2AuthenticationRequestRepository(cache);
        request = mock(HttpServletRequest.class);
        response = mock(HttpServletResponse.class);
        authenticationRequest = mock(AbstractSaml2AuthenticationRequest.class);
    }

    @Test
    void testLoadAuthenticationRequest_WithValidRelayState() {
        String relayState = "testRelayState";
        when(request.getParameter(Saml2ParameterNames.RELAY_STATE)).thenReturn(relayState);
        when(authenticationRequest.getRelayState()).thenReturn(relayState);
        cache.put(relayState, authenticationRequest);

        AbstractSaml2AuthenticationRequest result = repository.loadAuthenticationRequest(request);

        assertNotNull(result);
        assertEquals(authenticationRequest, result);
    }

    @Test
    void testSaveAuthenticationRequest() {
        String relayState = "testRelayState";
        when(authenticationRequest.getRelayState()).thenReturn(relayState);

        repository.saveAuthenticationRequest(authenticationRequest, request, response);

        assertEquals(authenticationRequest, cache.get(relayState, AbstractSaml2AuthenticationRequest.class));
    }

    @Test
    void testRemoveAuthenticationRequest() {
        String relayState = "testRelayState";
        when(request.getParameter(Saml2ParameterNames.RELAY_STATE)).thenReturn(relayState);
        when(authenticationRequest.getRelayState()).thenReturn(relayState);
        cache.put(relayState, authenticationRequest);

        AbstractSaml2AuthenticationRequest result = repository.removeAuthenticationRequest(request, response);

        assertNotNull(result);
        assertEquals(authenticationRequest, result);
        assertNull(cache.get(relayState, AbstractSaml2AuthenticationRequest.class));
    }
}
