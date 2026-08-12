package com.sandeep.eventrabackend.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class JwtAuthenticationFilterTests {

    private static final String REFRESH_TOKEN = "refresh.jwt.token";
    private static final String ACCESS_TOKEN = "access.jwt.token";

    @Mock
    private JwtTokenProvider jwtTokenProvider;
    @Mock
    private org.springframework.security.core.userdetails.UserDetailsService userDetailsService;
    @Mock
    private TokenBlacklistService tokenBlacklistService;
    @Mock
    private AuthCookieHelper authCookieHelper;
    @Mock
    private TokenRefreshQueueHandler tokenRefreshQueueHandler;

    private JwtAuthenticationFilter filter;

    @BeforeEach
    void setUp() {
        filter = new JwtAuthenticationFilter(
                jwtTokenProvider, userDetailsService, tokenBlacklistService, authCookieHelper, tokenRefreshQueueHandler);
        SecurityContextHolder.clearContext();
    }

    @Test
    @DisplayName("non-access JWT is rejected with 401 instead of continuing the chain (#15512)")
    void nonAccessTokenIsRejectedWith401() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Authorization", "Bearer " + REFRESH_TOKEN);
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = org.mockito.Mockito.mock(FilterChain.class);

        when(tokenBlacklistService.isBlacklisted(eq(REFRESH_TOKEN))).thenReturn(false);
        when(jwtTokenProvider.validateToken(REFRESH_TOKEN)).thenReturn(true);
        when(jwtTokenProvider.isAccessToken(REFRESH_TOKEN)).thenReturn(false);

        filter.doFilterInternal(request, response, chain);

        assertEquals(HttpServletResponse.SC_UNAUTHORIZED, response.getStatus());
        verify(chain, never()).doFilter(request, response);
        assertNull(SecurityContextHolder.getContext().getAuthentication());
    }

    @Test
    @DisplayName("access JWT authenticates and continues the filter chain (#15512)")
    void accessTokenAuthenticatesAndContinues() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Authorization", "Bearer " + ACCESS_TOKEN);
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = org.mockito.Mockito.mock(FilterChain.class);

        when(tokenBlacklistService.isBlacklisted(eq(ACCESS_TOKEN))).thenReturn(false);
        when(jwtTokenProvider.validateToken(ACCESS_TOKEN)).thenReturn(true);
        when(jwtTokenProvider.isAccessToken(ACCESS_TOKEN)).thenReturn(true);
        when(jwtTokenProvider.getUsernameFromToken(ACCESS_TOKEN)).thenReturn("user@example.com");
        when(jwtTokenProvider.getIssuedAtDateFromToken(ACCESS_TOKEN)).thenReturn(new java.util.Date());
        when(userDetailsService.loadUserByUsername("user@example.com"))
                .thenReturn(org.springframework.security.core.userdetails.User
                        .withUsername("user@example.com")
                        .password("x")
                        .authorities("ATTENDEE")
                        .build());

        filter.doFilterInternal(request, response, chain);

        assertEquals(HttpServletResponse.SC_OK, response.getStatus());
        verify(chain).doFilter(request, response);
    }
}
