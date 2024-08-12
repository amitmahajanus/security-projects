package com.sc.crmate.samlauth;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.cache.Cache;
import org.springframework.cache.concurrent.ConcurrentMapCache;
import org.springframework.security.saml2.core.Saml2ParameterNames;
import org.springframework.security.saml2.provider.service.authentication.AbstractSaml2AuthenticationRequest;
import org.springframework.security.saml2.provider.service.web.Saml2AuthenticationRequestRepository;
import org.springframework.stereotype.Repository;

import java.util.Enumeration;
import java.util.concurrent.ConcurrentHashMap;
@Repository
@RequiredArgsConstructor
public class CustomSaml2AuthenticationRequestRepository implements Saml2AuthenticationRequestRepository<AbstractSaml2AuthenticationRequest> {
    private final Cache cache = new ConcurrentMapCache("samlrequests");
    @Override
    public AbstractSaml2AuthenticationRequest loadAuthenticationRequest(HttpServletRequest request) {
        String relayState = request.getParameter(Saml2ParameterNames.RELAY_STATE);
        System.out.println("Fetching saml2 auth request by relay stage " + relayState);
        if(null == relayState) {
            return null;
        }
        Enumeration<String> params = request.getParameterNames();
        System.out.println(request.getRequestId());
        while(params.hasMoreElements()) {
            String p = params.nextElement();
            System.out.println(request.getParameter(p));
        }
        System.out.println("Fetching saml2 auth request by relay stage " + relayState);
        AbstractSaml2AuthenticationRequest authenticationRequest = this.cache.get(relayState, AbstractSaml2AuthenticationRequest.class);

        if(null == authenticationRequest || !authenticationRequest.getRelayState().equalsIgnoreCase(relayState)){
            System.out.println("Relay state received "  + relayState + " is different from what is saved " + authenticationRequest.getRelayState() );
            return null;
        }

        return authenticationRequest;
    }

    @Override
    public void saveAuthenticationRequest(AbstractSaml2AuthenticationRequest authenticationRequest, HttpServletRequest request, HttpServletResponse response) {
         String relayState = authenticationRequest.getRelayState();
        System.out.println("Relay state received " + relayState);
        this.cache.put(relayState, authenticationRequest);
    }

    @Override
    public AbstractSaml2AuthenticationRequest removeAuthenticationRequest(HttpServletRequest request, HttpServletResponse response) {
        AbstractSaml2AuthenticationRequest authenticationRequest = loadAuthenticationRequest(request);
        if(null == authenticationRequest) {
            return null;
        }
        System.out.println("Removing authentication request " + authenticationRequest.getId());
        cache.evict(authenticationRequest.getRelayState());
        return authenticationRequest;
    }
}
