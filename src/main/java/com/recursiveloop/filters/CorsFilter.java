// This file is property of Recursive Loop Ltd.
//
// Author: Rob Jinman
// Web: http://recursiveloop.org
// Copyright Recursive Loop Ltd 2015
// Copyright Rob Jinman 2015


package com.recursiveloop.filters;

import java.io.IOException;
import java.util.List;
import java.util.Arrays;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.logging.Logger;
import java.util.logging.Level;


/**
* Implements Cross-Origin Resource Sharing (CORS), the standard way of circumventing a web browser's Same Origin Policy (SOP).
*/
public class CorsFilter implements Filter {
  private final static Logger m_logger = Logger.getLogger(CorsFilter.class.getName());

  private String[] m_allowedOrigins = {"*"};
  private String m_allowedMethods = "GET,POST,HEAD,OPTIONS,PUT";
  private List<String> m_lstAllowedMethods = null;
  private String m_allowedHeaders = "Content-Type,X-Requested-With,accept,Origin,Access-Control-Request-Method,Access-Control-Request-Headers";
  private List<String> m_lstAllowedHeaders = null;
  private String m_exposedHeaders = "Access-Control-Allow-Origin,Access-Control-Allow-Credentials";
  private boolean m_supportCredentials = true;
  private String m_preflightMaxAge = "1000";

  /**
  * Initialises the filter.
  */
  public void init(FilterConfig config) throws ServletException {
    String sAllowedOrigins = config.getInitParameter("cors.allowed.origins");
    String sAllowedMethods = config.getInitParameter("cors.allowed.methods");
    String sAllowedHeaders = config.getInitParameter("cors.allowed.headers");
    String sExposedHeaders = config.getInitParameter("cors.exposed.headers");
    String sSupportCredentials = config.getInitParameter("cors.support.credentials");
    String sPreflightMaxAge = config.getInitParameter("cors.preflight.maxage");

    if (sAllowedOrigins != null) {
      m_allowedOrigins = sAllowedOrigins.toLowerCase().split("\\s*,\\s*");
    }

    if (sAllowedMethods != null) {
      m_allowedMethods = sAllowedMethods;
      m_lstAllowedMethods = Arrays.asList(m_allowedMethods.toLowerCase().split("\\s*,\\s*"));
    }

    if (sAllowedHeaders != null) {
      m_allowedHeaders = sAllowedHeaders;
      m_lstAllowedHeaders = Arrays.asList(m_allowedHeaders.toLowerCase().split("\\s*,\\s*"));
    }

    if (sExposedHeaders != null) {
      m_exposedHeaders = sExposedHeaders;
    }

    if (sSupportCredentials != null) {
      m_supportCredentials = sSupportCredentials.equals("true");
    }

    if (sPreflightMaxAge != null) {
      m_preflightMaxAge = sPreflightMaxAge;
    }
  }

  /**
  * Modifies the response accordingly and passes it to the next filter in the chain.
  */
  public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
    throws IOException, ServletException {

    HttpServletRequest request = (HttpServletRequest)req;
    HttpServletResponse response = (HttpServletResponse)res;

    String origin = request.getHeader("Origin");
    if (origin != null) {

      // Handle preflight requests
      if (request.getMethod().equals("OPTIONS")) {
        String method = request.getHeader("Access-Control-Request-Method");
        String strHeaders = request.getHeader("Access-Control-Request-Headers");

        if (method == null || strHeaders == null) {
          chain.doFilter(request, response);
          return;
        }

        List<String> headers = Arrays.asList(strHeaders.split("\\s*,\\s*"));

        if (!m_lstAllowedMethods.contains(method.toLowerCase())) {
          chain.doFilter(request, response);
          return;
        }

        for (String hdr : headers) {
          if (!m_lstAllowedHeaders.contains(hdr.toLowerCase())) {
            chain.doFilter(request, response);
            return;
          }
        }

        response.setHeader("Access-Control-Max-Age", m_preflightMaxAge);
      }

      boolean matchFound = false;
      for (String s : m_allowedOrigins) {
        if (matchFound = match(origin, s)) {
          response.setHeader("Access-Control-Allow-Origin", origin);
          break;
        }
      }

      if (matchFound) {
        response.setHeader("Access-Control-Allow-Methods", m_allowedMethods);
        response.setHeader("Access-Control-Allow-Headers", m_allowedHeaders);
        response.setHeader("Access-Control-Expose-Headers", m_exposedHeaders);
        response.setHeader("Access-Control-Allow-Credentials", m_supportCredentials ? "true" : "false");
      }
    }

    chain.doFilter(request, response);
  }

  /**
  * Performs cleanup operations.
  */
  public void destroy() {}

  /**
  * Matches a url with a pattern.
  */
  private boolean match(String url, String pattern) {
    return pattern.equals("*") || url.equals(pattern);
  }
}
