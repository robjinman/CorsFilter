com.recursiveloop.filters.CorsFilter
====================================

An implementation of javax.servlet.Filter that performs Cross Origin Resource Sharing (CORS), the standard method of circumventing a browser's Same Origin Policy (SOP).

The filter should be configured in the web application's deployment descriptor (web.xml) with the following parameters:

    <filter>
      <filter-name>CorsFilter</filter-name>
      <filter-class>com.recursiveloop.filters.CorsFilter</filter-class>
      <init-param>
        <param-name>cors.allowed.origins</param-name>
        <param-value>http://www.example.com</param-value>
      </init-param>
      <init-param>
        <param-name>cors.allowed.methods</param-name>
        <param-value>GET,POST,HEAD,OPTIONS,PUT</param-value>
      </init-param>
      <init-param>
        <param-name>cors.allowed.headers</param-name>
        <param-value>Content-Type,X-Requested-With,accept,Origin,Access-Control-Request-Method,Access-Control-Request-Headers</param-value>
      </init-param>
      <init-param>
        <param-name>cors.exposed.headers</param-name>
        <param-value>Access-Control-Allow-Origin,Access-Control-Allow-Credentials</param-value>
      </init-param>
      <init-param>
        <param-name>cors.support.credentials</param-name>
        <param-value>true</param-value>
      </init-param>
      <init-param>
        <param-name>cors.preflight.maxage</param-name>
        <param-value>10</param-value>
      </init-param>
    </filter>
