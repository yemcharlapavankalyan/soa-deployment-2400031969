package com.klef.ms.security;

import java.io.IOException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.klef.ms.service.UserService;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;


@Component
public class JwtFilter extends OncePerRequestFilter
{
    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private UserService service;


    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain chain)
            throws ServletException, IOException
    {

        // =====================================================
        // GET REQUEST URI
        // =====================================================

        String requestURI =
                request.getRequestURI();


        System.out.println();
        System.out.println("======================================");
        System.out.println("JWT FILTER");
        System.out.println("Request URI : " + requestURI);
        System.out.println("Servlet Path: " + request.getServletPath());
        System.out.println("======================================");


        // =====================================================
        // PUBLIC ENDPOINTS
        // =====================================================

        boolean isPublicEndpoint =
                requestURI.endsWith("/user/")
                || requestURI.endsWith("/user/test")
                || requestURI.endsWith("/user/login")
                || requestURI.endsWith("/user/add")
                || requestURI.startsWith("/swagger-ui")
                || requestURI.startsWith("/v3/api-docs")
                || requestURI.startsWith("/actuator");


        // =====================================================
        // SKIP JWT VALIDATION FOR PUBLIC ENDPOINTS
        // =====================================================

        if (isPublicEndpoint)
        {

            System.out.println(
                    "Public Endpoint - JWT validation skipped"
            );

            chain.doFilter(
                    request,
                    response
            );

            return;
        }


        // =====================================================
        // PROTECTED ENDPOINT
        // =====================================================

        System.out.println(
                "Protected Endpoint - JWT validation required"
        );


        // =====================================================
        // READ AUTHORIZATION HEADER
        // =====================================================

        String header =
                request.getHeader("Authorization");


        System.out.println(
                "Authorization Header = "
                + header
        );


        // =====================================================
        // CHECK BEARER TOKEN
        // =====================================================

        if (header == null ||
                !header.startsWith("Bearer "))
        {

            sendErrorResponse(
                    response,
                    401,
                    "Authorization header is missing or invalid"
            );

            return;
        }


        // =====================================================
        // EXTRACT TOKEN
        // =====================================================

        String token =
                header.substring(7).trim();


        try
        {

            // =================================================
            // EXTRACT USERNAME FROM JWT
            // =================================================

            String username =
                    jwtUtil.extractUsername(token);


            System.out.println(
                    "Username from JWT = "
                    + username
            );


            // =================================================
            // CHECK AUTHENTICATION
            // =================================================

            if (SecurityContextHolder
                    .getContext()
                    .getAuthentication() == null)
            {

                // =============================================
                // LOAD USER FROM DATABASE
                // =============================================

                UserDetails userDetails =
                        service.loadUserByUsername(
                                username
                        );


                // =============================================
                // VALIDATE JWT
                // =============================================

                if (userDetails != null &&
                        jwtUtil.validateToken(
                                token,
                                userDetails
                        ))
                {

                    // =========================================
                    // CREATE AUTHENTICATION OBJECT
                    // =========================================

                    UsernamePasswordAuthenticationToken
                            authToken =
                            new UsernamePasswordAuthenticationToken(
                                    userDetails,
                                    null,
                                    userDetails.getAuthorities()
                            );


                    // =========================================
                    // ADD REQUEST DETAILS
                    // =========================================

                    authToken.setDetails(
                            new WebAuthenticationDetailsSource()
                                    .buildDetails(request)
                    );


                    // =========================================
                    // STORE AUTHENTICATION
                    // =========================================

                    SecurityContextHolder
                            .getContext()
                            .setAuthentication(
                                    authToken
                            );


                    System.out.println(
                            "JWT validation successful"
                    );

                    System.out.println(
                            "User Authorities = "
                            + userDetails.getAuthorities()
                    );

                }
                else
                {

                    sendErrorResponse(
                            response,
                            401,
                            "Invalid or expired token"
                    );

                    return;
                }
            }

        }
        catch (Exception e)
        {

            e.printStackTrace();

            sendErrorResponse(
                    response,
                    401,
                    "Invalid token"
            );

            return;
        }


        // =====================================================
        // CONTINUE REQUEST
        // =====================================================

        chain.doFilter(
                request,
                response
        );
    }


    // =========================================================
    // SEND ERROR RESPONSE
    // =========================================================

    private void sendErrorResponse(
            HttpServletResponse response,
            int status,
            String message)
            throws IOException
    {

        response.setStatus(status);

        response.setContentType(
                "application/json"
        );

        response.setCharacterEncoding(
                "UTF-8"
        );


        String jsonResponse =
                "{\"error\":\"Unauthorized\",\"message\":\""
                + message
                + "\"}";


        response.getWriter().write(
                jsonResponse
        );
    }
}