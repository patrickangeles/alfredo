/**
 * Licensed to Cloudera, Inc. under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. Cloudera, Inc. licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.cloudera.alfredo.server;

import com.cloudera.alfredo.client.AuthenticatedURL;
import com.cloudera.alfredo.client.AuthenticationException;
import com.cloudera.alfredo.util.Signer;
import com.cloudera.alfredo.util.SignerException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.Principal;
import java.util.Enumeration;
import java.util.Properties;
import java.util.Random;

/**
 * The <code>AuthenticationFilter</code> enabled protecting web application resources with different (pluggable)
 * authentication mechanisms.
 * <p/>
 * Out of the box it provides 2 authentication mechanims: Pseudo and Kerberos SPNEGO.
 * <p/>
 * Additional authentication mechanisms are supported via the {@link AuthenticationHandler} interface.
 * <p/>
 * This filter delegates to the configured authentication handler for authentication and once it obtains an
 * {@link AuthenticationToken} from it sets a signed HTTP Cookie with the token. For client requests
 * that provide the signed HTTP Cookie, it verifies the validity of the cookie, extract the user information
 * and let the request proceed to the target resource.
 * <p/>
 * The supported configuration properties are:
 * <ul>
 *   <li>config.prefix: indicates the prefix to be used by all other configuration properties, the default value
 *   is no prefix. See below for details on how/why this prefix is used.</li>
 *   <li>[#PREFIX#.]type: simple|kerberos|#CLASS#, 'simple' is short for the
 *   {@link PseudoAuthenticationHandler}, 'kerberos' is short for {@link KerberosAuthenticationHandler}, otherwise
 *   the full class name of the {@link AuthenticationHandler} must be specified.</li>
 *   <li>[#PREFIX#.]signature.secret: the secret used to sign the HTTP Cookie value, the default value is a random
 *   value (unless multiple webapp instances need to share the secret the random value is adequate.</li>
 *   <li>[#PREFIX#.]token.validity: validity -in seconds- of the generated token is valid before a
 *       new authentication is triggered, default value is <code>3600</code> seconds</li>
 * </ul>
 * <p/>
 * The rest of the configuration properties are specific to the {@link AuthenticationHandler} implementation and the
 * <code>AuthenticationFilter</code> will take all the properties that start with the prefix #PREFIX#, it will remove
 * the prefix from it and it will pass them to the the authentication handler for initialization. Properties that do
 * not start with the prefix will not be passed to the authentication handler initialization.
 */
public class AuthenticationFilter implements Filter {

    private static Logger LOG = LoggerFactory.getLogger(AuthenticationFilter.class);

    /**
     * Constant for the property that specifies the configuration prefix.
     */
    public static final String CONFIG_PREFIX = "config.prefix";

    /**
     * Constant for the property that specifies the authentication handler to use.
     */
    public static final String AUTH_TYPE = "type";

    /**
     * Constant for the property that specifies the secret to use for signing the HTTP Cookies.
     */
    public static final String SIGNATURE_SECRET = "signature.secret";

    /**
     * Constant for the configuration property that indicates the validity of the generated token.
     */
    public static final String AUTH_TOKEN_VALIDITY = "token.validity";

    private Signer signer;
    private AuthenticationHandler authHandler;
    private boolean randomSecret;
    private long validity;

    /**
     * Initializes the authentication filter.
     * <p/>
     * It instantiates and initializes the specified {@link AuthenticationHandler}.
     * <p/>
     *
     * @param filterConfig filter configuration.
     * @throws ServletException thrown if the filter or the authentication handler could not be initialized properly.
     */
    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        String configPrefix = filterConfig.getInitParameter(CONFIG_PREFIX);
        configPrefix = (configPrefix != null) ? configPrefix + "." : "";
        Properties config = getConfiguration(configPrefix, filterConfig);
        String authHandlerName = config.getProperty(AUTH_TYPE, null);
        String authHandlerClassName;
        if (authHandlerName == null) {
            throw new ServletException("Authentication type must be specified: simple|kerberos|<class>");
        }
        if (authHandlerName.equals("simple")) {
            authHandlerClassName = PseudoAuthenticationHandler.class.getName();
        }
        else if (authHandlerName.equals("kerberos")) {
            authHandlerClassName = KerberosAuthenticationHandler.class.getName();
        }
        else {
            authHandlerClassName = authHandlerName;
        }

        try {
            Class klass = Thread.currentThread().getContextClassLoader().loadClass(authHandlerClassName);
            authHandler = (AuthenticationHandler) klass.newInstance();
            authHandler.init(config);
        }
        catch (ClassNotFoundException ex) {
            throw new ServletException(ex);
        }
        catch (InstantiationException ex) {
            throw new ServletException(ex);
        }
        catch (IllegalAccessException ex) {
            throw new ServletException(ex);
        }
        String signatureSecret = config.getProperty(configPrefix + SIGNATURE_SECRET);
        if (signatureSecret == null) {
            signatureSecret = Long.toString(new Random(System.currentTimeMillis()).nextLong());
            randomSecret = true;
            LOG.warn("'signature.secret' configuration not set, using a random value as secret");
        }
        signer = new Signer(signatureSecret.getBytes());
        validity = Long.parseLong(config.getProperty(AUTH_TOKEN_VALIDITY, "3600")) * 1000; //10 hours
    }

    /**
     * Returns the authentication handler being used.
     *
     * @return the authentication handler being used.
     */
    protected AuthenticationHandler getAuthenticationHandler() {
        return authHandler;
    }

    /**
     * Returns if a random secret is being used.
     *
     * @return if a random secret is being used.
     */
    protected boolean isRandomSecret() {
        return randomSecret;
    }

    /**
     * Returns the validity of the generated tokens.
     *
     * @return the validity of the generated tokens, in seconds.
     */
    protected long getValidity() {
        return validity / 1000;
    }

    /**
     * Destroys the filter.
     * <p/>
     * It invokes the {@link AuthenticationHandler#destroy()} method to release any resources it may hold.
     */
    @Override
    public void destroy
            () {
        if (authHandler != null) {
            authHandler.destroy();
            authHandler = null;
        }
    }

    /**
     * Returns the filtered configuration (only properties starting with the specified prefix). The property keys
     * are also trimmed from the prefix. The returned <code>Properties</code> object is used to initialized the
     * {@link AuthenticationHandler}.
     * <p/>
     * This method can be overriden by subclasses to obtain the configuration from other configuration source than
     * the web.xml file.
     *
     * @param configPrefix configuration prefix to use for extracting configuration properties.
     * @param filterConfig filter configuration object
     * @return the configuration to be used with the {@link AuthenticationHandler} instance.
     *
     * @throws ServletException thrown if the configuration could not be created.
     */
    protected Properties getConfiguration(String configPrefix, FilterConfig filterConfig) throws ServletException {
        Properties props = new Properties();
        Enumeration names = filterConfig.getInitParameterNames();
        while (names.hasMoreElements()) {
            String name = (String) names.nextElement();
            if (name.startsWith(configPrefix)) {
                String value = filterConfig.getInitParameter(name);
                props.put(name.substring(configPrefix.length()), value);
            }
        }
        return props;
    }

    /**
     * Returns the full URL of the request including the query string.
     * <p/>
     * Used as a convenience method for logging purposes.
     *
     * @param request the request object.
     * @return the full URL of the request including the query string.
     */
    protected String getRequestURL(HttpServletRequest request) {
        StringBuffer sb = request.getRequestURL();
        if (request.getQueryString() != null) {
            sb.append("?").append(request.getQueryString());
        }
        return sb.toString();
    }

    /**
     * Returns the {@link AuthenticationToken} for the request.
     * <p/>
     * It looks a the received HTTP Cookies and extracts the value of the {@link AuthenticatedURL#AUTH_COOKIE}
     * if present. It verifies the signature and if correct it creates the {@link AuthenticationToken} and returns
     * it.
     * <p/>
     * If this method returns <code>null</code> the filter will invoke the configured {@link AuthenticationHandler}
     * to perform user authentication.
     * 
     * @param request request object.
     * @return the Authentication token if the request is authentiated, <code>null</code> otherwise.
     * @throws IOException thrown if an IO error occurred.
     * @throws AuthenticationException thrown if the token is invalid/tampered or if it has expired.
     */
    protected AuthenticationToken getToken(HttpServletRequest request) throws IOException, AuthenticationException {
        AuthenticationToken token = null;
        String tokenStr = null;
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals(AuthenticatedURL.AUTH_COOKIE)) {
                    tokenStr = cookie.getValue();
                    try {
                        tokenStr = signer.verifyAndExtract(tokenStr);
                    }
                    catch (SignerException ex) {
                        throw new AuthenticationException(ex);
                    }
                    break;
                }
            }
        }
        if (tokenStr != null) {
            token = AuthenticationToken.parse(tokenStr);
            if (token.isExpired()) {
                throw new AuthenticationException("AuthenticationToken expired");
            }
        }
        return token;
    }

    /**
     * If the request has a valid authentication token it allows the request to continue to the target resource,
     * otherwise it triggers an authentication sequence using the configured {@link AuthenticationHandler}.
     *
     * @param request the request object.
     * @param response the response object.
     * @param filterChain the filter chain object.
     * @throws IOException thrown if an IO error occurred.
     * @throws ServletException thrown if a processing error occurred.
     */
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain filterChain)
            throws IOException, ServletException {
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;
        try {
            boolean newToken = false;
            AuthenticationToken token = getToken(httpRequest);
            if (token == null) {
                LOG.debug("Request [{}] triggering authentication", getRequestURL(httpRequest));
                token = authHandler.authenticate(httpRequest, httpResponse);
                if (token != null && token != AuthenticationToken.ANNONYMOUS) {
                    token.setExpires(System.currentTimeMillis() + validity);
                }
                newToken = true;
            }
            if (token != null) {
                LOG.debug("Request [{}] user [{}] authenticated", getRequestURL(httpRequest), token.getUserName());
                final AuthenticationToken authToken = token;
                httpRequest = new HttpServletRequestWrapper(httpRequest) {

                    @Override
                    public String getAuthType() {
                        return authToken.getType();
                    }

                    @Override
                    public String getRemoteUser() {
                        return authToken.getUserName();
                    }

                    @Override
                    public Principal getUserPrincipal() {
                        return (authToken != AuthenticationToken.ANNONYMOUS) ? authToken : null;
                    }
                };
                if (newToken && token != AuthenticationToken.ANNONYMOUS) {
                    String signedToken = signer.sign(token.toString());
                    httpResponse.addCookie(new Cookie(AuthenticatedURL.AUTH_COOKIE, signedToken));
                }
                filterChain.doFilter(httpRequest, httpResponse);
            }
        }
        catch (AuthenticationException ex) {
            if (!httpResponse.isCommitted()) {
                Cookie cookie = new Cookie(AuthenticatedURL.AUTH_COOKIE, "");
                cookie.setMaxAge(0);
                httpResponse.addCookie(cookie);
                httpResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED, ex.getMessage());
            }
            LOG.warn("Authentication exception: " + ex.getMessage());
        }
    }

}
