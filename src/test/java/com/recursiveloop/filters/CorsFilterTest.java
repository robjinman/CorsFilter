// This file is property of Recursive Loop Ltd.
//
// Author: Rob Jinman
// Web: http://recursiveloop.org
// Copyright Recursive Loop Ltd 2015
// Copyright Rob Jinman 2015


package com.recursiveloop.filters;

import static org.mockito.Mockito.*;
import org.mockito.ArgumentCaptor;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.Assert;
import javax.servlet.ServletException;
import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.FilterConfig;
import java.util.Arrays;
import java.io.IOException;


/**
* Verifies that com.recursiveloop.filters.CorsFilter conforms to
* the specification at http://www.w3.org/TR/2014/REC-cors-20140116/
*/
public class CorsFilterTest {
  private CorsFilter m_filter;
  private FilterConfig m_config;
  private HttpServletRequest m_request;
  private HttpServletResponse m_response;
  private FilterChain m_chain;

  private boolean containsOnly(String sA, String sB) {
    String[] sAItems = sA.trim().split("\\s*,\\s*");
    String[] sBItems = sB.trim().split("\\s*,\\s*");
    Arrays.sort(sAItems);
    Arrays.sort(sBItems);

    return Arrays.equals(sAItems, sBItems);
  }

  @Before
  public void before() {
    m_filter = new CorsFilter();
    m_config = mock(FilterConfig.class);
    m_request = mock(HttpServletRequest.class);
    m_response = mock(HttpServletResponse.class);
    m_chain = mock(FilterChain.class);

    when(m_config.getInitParameter("cors.allowed.origins")).thenReturn("www.example.com");
    when(m_config.getInitParameter("cors.allowed.methods")).thenReturn("GET,POST,HEAD,OPTIONS,PUT");
    when(m_config.getInitParameter("cors.allowed.headers")).thenReturn("some-header, some-other-header, my-header");
    when(m_config.getInitParameter("cors.exposed.headers")).thenReturn("header-one, header-two,header-three");
    when(m_config.getInitParameter("cors.support.credentials")).thenReturn("true");
    when(m_config.getInitParameter("cors.preflight.maxage")).thenReturn("10");
  }

  /**
  * REC-CORS Section 6.1.1
  * "If the Origin header is not present terminate this set of steps.
  * The request is outside the scope of this specification."
  *
  * This implementation will return a non-CORS response in this case.
  */
  @Test
  public void actual_6_1_1() throws IOException, ServletException {
    when(m_request.getMethod()).thenReturn("PUT");

    m_filter.init(m_config);
    m_filter.doFilter(m_request, m_response, m_chain);

    verify(m_response, never()).setHeader(eq("Access-Control-Allow-Origin"), any(String.class));
  }

  /**
  * REC-CORS Section 6.1.2
  * "If the value of the Origin header is not a case-sensitive match for any
  * of the values in list of origins, do not set any additional headers and
  * terminate this set of steps."
  *
  * This implementation will return a non-CORS response in this case.
  */
  @Test
  public void actual_6_1_2() throws IOException, ServletException {
    when(m_request.getMethod()).thenReturn("PUT");
    when(m_request.getHeader("Origin")).thenReturn("www.website.com");

    m_filter.init(m_config);
    m_filter.doFilter(m_request, m_response, m_chain);

    verify(m_response, never()).setHeader(eq("Access-Control-Allow-Origin"), any(String.class));
  }

  /**
  * REC-CORS Section 6.1.3 1
  * "If the resource supports credentials add a single Access-Control-Allow-Origin
  * header, with the value of the Origin header as value, and add a single
  * Access-Control-Allow-Credentials header with the case-sensitive string "true"
  * as value."
  *
  * With cors.support.credentials = true
  */
  @Test
  public void actual_6_1_3_1() throws IOException, ServletException {
    when(m_config.getInitParameter("cors.support.credentials")).thenReturn("true");

    when(m_request.getMethod()).thenReturn("PUT");
    when(m_request.getHeader("Origin")).thenReturn("www.example.com");

    m_filter.init(m_config);
    m_filter.doFilter(m_request, m_response, m_chain);

    verify(m_response).setHeader("Access-Control-Allow-Origin", "www.example.com");
    verify(m_response).setHeader("Access-Control-Allow-Credentials", "true");
  }

  /**
  * REC-CORS Section 6.1.3 2
  * "If the resource supports credentials add a single Access-Control-Allow-Origin header,
  * with the value of the Origin header as value, and add a single
  * Access-Control-Allow-Credentials header with the case-sensitive string "true" as value."
  *
  * With cors.support.credentials = false
  * This implementation does not add an Access-Control-Allow-Credentials header in this case.
  */
  @Test
  public void actual_6_1_3_2() throws IOException, ServletException {
    when(m_config.getInitParameter("cors.support.credentials")).thenReturn("false");

    when(m_request.getMethod()).thenReturn("PUT");
    when(m_request.getHeader("Origin")).thenReturn("www.example.com");

    m_filter.init(m_config);
    m_filter.doFilter(m_request, m_response, m_chain);

    verify(m_response).setHeader("Access-Control-Allow-Origin", "www.example.com");
    verify(m_response, never()).setHeader(eq("Access-Control-Allow-Credentials"), any(String.class));
  }

  /**
  * REC-CORS Section 6.1.4
  * "If the list of exposed headers is not empty add one or more Access-Control-Expose-Headers
  * headers, with as values the header field names given in the list of exposed headers."
  */
  @Test
  public void actual_6_1_4() throws IOException, ServletException {
    when(m_request.getMethod()).thenReturn("PUT");
    when(m_request.getHeader("Origin")).thenReturn("www.example.com");

    m_filter.init(m_config);
    m_filter.doFilter(m_request, m_response, m_chain);

    verify(m_response).setHeader("Access-Control-Allow-Origin", "www.example.com");

    ArgumentCaptor<String> stringArgs = ArgumentCaptor.forClass(String.class);
    verify(m_response).setHeader(eq("Access-Control-Expose-Headers"), stringArgs.capture());
    Assert.assertTrue(containsOnly(stringArgs.getValue(), "header-two,header-three, header-one"));
  }

  /**
  * REC-CORS Section 6.2.1
  * "If the Origin header is not present terminate this set of steps. The request is outside
  * the scope of this specification."
  *
  * This implementation will return a non-CORS response in this case.
  */
  @Test
  public void preflight_6_2_1() throws IOException, ServletException {
    when(m_request.getMethod()).thenReturn("OPTIONS");
    when(m_request.getHeader("Access-Control-Request-Method")).thenReturn("PUT");
    when(m_request.getHeader("Access-Control-Request-Headers")).thenReturn("my-header");

    m_filter.init(m_config);
    m_filter.doFilter(m_request, m_response, m_chain);

    verify(m_response, never()).setHeader(eq("Access-Control-Allow-Origin"), any(String.class));
  }

  /**
  * REC-CORS Section 6.2.2
  * "If the value of the Origin header is not a case-sensitive match for any of the values in
  * list of origins do not set any additional headers and terminate this set of steps."
  *
  * This implementation will return a non-CORS response in this case.
  */
  @Test
  public void preflight_6_2_2() throws IOException, ServletException {
    when(m_request.getMethod()).thenReturn("OPTIONS");
    when(m_request.getHeader("Access-Control-Request-Method")).thenReturn("PUT");
    when(m_request.getHeader("Access-Control-Request-Headers")).thenReturn("my-header");
    when(m_request.getHeader("Origin")).thenReturn("www.website.com");

    m_filter.init(m_config);
    m_filter.doFilter(m_request, m_response, m_chain);

    verify(m_response, never()).setHeader(eq("Access-Control-Allow-Origin"), any(String.class));
  }

  /**
  * REC-CORS Section 6.2.3
  * "If there is no Access-Control-Request-Method header or if parsing failed, do not set any
  * additional headers and terminate this set of steps. The request is outside the scope of
  * this specification."
  *
  * This implementation will return a non-CORS response in this case.
  */
  @Test
  public void preflight_6_2_3() throws IOException, ServletException {
    when(m_request.getMethod()).thenReturn("OPTIONS");
    when(m_request.getHeader("Access-Control-Request-Headers")).thenReturn("my-header");
    when(m_request.getHeader("Origin")).thenReturn("www.example.com");

    m_filter.init(m_config);
    m_filter.doFilter(m_request, m_response, m_chain);

    verify(m_response, never()).setHeader(eq("Access-Control-Allow-Origin"), any(String.class));
  }

  /**
  * REC-CORS Section 6.2.4
  * (a) "If there are no Access-Control-Request-Headers headers let header field-names be the
  * empty list."
  * (b) "If parsing failed do not set any additional headers and terminate this set of steps.
  * The request is outside the scope of this specification."
  *
  * In this implementation, parsing always succeeds, so (b) is redundant.
  */
  @Test
  public void preflight_6_2_4() throws IOException, ServletException {
    when(m_request.getMethod()).thenReturn("OPTIONS");
    when(m_request.getHeader("Access-Control-Request-Method")).thenReturn("PUT");
    when(m_request.getHeader("Origin")).thenReturn("www.example.com");

    m_filter.init(m_config);
    m_filter.doFilter(m_request, m_response, m_chain);

    verify(m_response).setHeader("Access-Control-Allow-Origin", "www.example.com");
  }

  /**
  * REC-CORS Section 6.2.5
  * "If method is not a case-sensitive match for any of the values in list of methods do not
  * set any additional headers and terminate this set of steps."
  *
  * This implementation will return a non-CORS response in this case.
  */
  @Test
  public void preflight_6_2_5() throws IOException, ServletException {
    when(m_request.getMethod()).thenReturn("OPTIONS");
    when(m_request.getHeader("Access-Control-Request-Method")).thenReturn("BLAH");
    when(m_request.getHeader("Access-Control-Request-Headers")).thenReturn("my-header");
    when(m_request.getHeader("Origin")).thenReturn("www.example.com");

    m_filter.init(m_config);
    m_filter.doFilter(m_request, m_response, m_chain);

    verify(m_response, never()).setHeader(eq("Access-Control-Allow-Origin"), any(String.class));
  }

  /**
  * REC-CORS Section 6.2.6
  * "If any of the header field-names is not a ASCII case-insensitive match for any of the values
  * in list of headers do not set any additional headers and terminate this set of steps."
  *
  * This implementation will return a non-CORS response in this case.
  */
  @Test
  public void preflight_6_2_6() throws IOException, ServletException {
    when(m_request.getMethod()).thenReturn("OPTIONS");
    when(m_request.getHeader("Access-Control-Request-Method")).thenReturn("PUT");
    when(m_request.getHeader("Access-Control-Request-Headers")).thenReturn("unsupported-header");
    when(m_request.getHeader("Origin")).thenReturn("www.example.com");

    m_filter.init(m_config);
    m_filter.doFilter(m_request, m_response, m_chain);

    verify(m_response, never()).setHeader(eq("Access-Control-Allow-Origin"), any(String.class));
  }

  /**
  * REC-CORS Section 6.2.7 1
  * "If the resource supports credentials add a single Access-Control-Allow-Origin header, with
  * the value of the Origin header as value, and add a single Access-Control-Allow-Credentials
  * header with the case-sensitive string "true" as value."
  *
  * With cors.support.credentials = true
  */
  @Test
  public void preflight_6_2_7_1() throws IOException, ServletException {
    when(m_config.getInitParameter("cors.support.credentials")).thenReturn("true");

    when(m_request.getMethod()).thenReturn("OPTIONS");
    when(m_request.getHeader("Access-Control-Request-Method")).thenReturn("PUT");
    when(m_request.getHeader("Access-Control-Request-Headers")).thenReturn("my-header");
    when(m_request.getHeader("Origin")).thenReturn("www.example.com");

    m_filter.init(m_config);
    m_filter.doFilter(m_request, m_response, m_chain);

    verify(m_response).setHeader("Access-Control-Allow-Origin", "www.example.com");
    verify(m_response).setHeader("Access-Control-Allow-Credentials", "true");
  }

  /**
  * REC-CORS Section 6.2.7 2
  * "If the resource supports credentials add a single Access-Control-Allow-Origin header, with
  * the value of the Origin header as value, and add a single Access-Control-Allow-Credentials
  * header with the case-sensitive string "true" as value."
  *
  * With cors.support.credentials = false
  * This implementation does not add an Access-Control-Allow-Credentials header in this case.
  */
  @Test
  public void preflight_6_2_7_2() throws IOException, ServletException {
    when(m_config.getInitParameter("cors.support.credentials")).thenReturn("false");

    when(m_request.getMethod()).thenReturn("OPTIONS");
    when(m_request.getHeader("Access-Control-Request-Method")).thenReturn("PUT");
    when(m_request.getHeader("Access-Control-Request-Headers")).thenReturn("my-header");
    when(m_request.getHeader("Origin")).thenReturn("www.example.com");

    m_filter.init(m_config);
    m_filter.doFilter(m_request, m_response, m_chain);

    verify(m_response).setHeader("Access-Control-Allow-Origin", "www.example.com");
    verify(m_response, never()).setHeader(eq("Access-Control-Allow-Credentials"), any(String.class));
  }

  /**
  * REC-CORS Section 6.2.8
  * "Optionally add a single Access-Control-Max-Age header with as value the amount of seconds
  * the user agent is allowed to cache the result of the request."
  *
  * This implementation always adds an Access-Control-Max-Age header.
  */
  @Test
  public void preflight_6_2_8() throws IOException, ServletException {
    when(m_request.getMethod()).thenReturn("OPTIONS");
    when(m_request.getHeader("Access-Control-Request-Method")).thenReturn("PUT");
    when(m_request.getHeader("Access-Control-Request-Headers")).thenReturn("my-header");
    when(m_request.getHeader("Origin")).thenReturn("www.example.com");

    m_filter.init(m_config);
    m_filter.doFilter(m_request, m_response, m_chain);

    verify(m_response).setHeader("Access-Control-Allow-Origin", "www.example.com");
    verify(m_response).setHeader("Access-Control-Max-Age", "10");
  }

  /**
  * REC-CORS Section 6.2.9
  * "Add one or more Access-Control-Allow-Methods headers consisting of (a subset of) the list
  * of methods."
  */
  @Test
  public void preflight_6_2_9() throws IOException, ServletException {
    when(m_request.getMethod()).thenReturn("OPTIONS");
    when(m_request.getHeader("Access-Control-Request-Method")).thenReturn("PUT");
    when(m_request.getHeader("Access-Control-Request-Headers")).thenReturn("my-header");
    when(m_request.getHeader("Origin")).thenReturn("www.example.com");

    m_filter.init(m_config);
    m_filter.doFilter(m_request, m_response, m_chain);

    verify(m_response).setHeader("Access-Control-Allow-Origin", "www.example.com");

    ArgumentCaptor<String> stringArgs = ArgumentCaptor.forClass(String.class);
    verify(m_response).setHeader(eq("Access-Control-Allow-Methods"), stringArgs.capture());
    Assert.assertTrue(containsOnly(stringArgs.getValue(), "PUT, OPTIONS, HEAD, POST, GET"));
  }

  /**
  * REC-CORS Section 6.2.10
  * "Add one or more Access-Control-Allow-Headers headers consisting of (a subset of) the list
  * of headers."
  */
  @Test
  public void preflight_6_2_10() throws IOException, ServletException {
    when(m_request.getMethod()).thenReturn("OPTIONS");
    when(m_request.getHeader("Access-Control-Request-Method")).thenReturn("PUT");
    when(m_request.getHeader("Access-Control-Request-Headers")).thenReturn("my-header");
    when(m_request.getHeader("Origin")).thenReturn("www.example.com");

    m_filter.init(m_config);
    m_filter.doFilter(m_request, m_response, m_chain);

    verify(m_response).setHeader("Access-Control-Allow-Origin", "www.example.com");

    ArgumentCaptor<String> stringArgs = ArgumentCaptor.forClass(String.class);
    verify(m_response).setHeader(eq("Access-Control-Allow-Headers"), stringArgs.capture());
    Assert.assertTrue(containsOnly(stringArgs.getValue(), "some-other-header,my-header, some-header"));
  }

  @After
  public void after() {
    m_filter.destroy();
  }
}
