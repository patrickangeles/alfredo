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

import com.cloudera.alfredo.client.AuthenticationException;
import com.cloudera.alfredo.client.KerberosAuthenticator;
import com.sun.security.auth.module.Krb5LoginModule;
import org.apache.commons.codec.binary.Base64;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.Subject;
import javax.security.auth.kerberos.KerberosPrincipal;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.IOException;
import java.security.Principal;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

/**
 * The <code>KerberosAuthenticationHandler</code> implements the Kerberos SPNEGO authentication mechanims for HTTP.
 * <p/>
 * The supported configuration properties are:
 * <ul>
 *   <li>kerberos.principal: the Kerberos principal to used by the server. As stated by the Kerberos SPNEGO
 *   specification, it should be <code>HTTP/${HOSTNAME}@{REALM}</code>. The realm can be ommitted from the
 *   principal as the JDK GSS libraries will use the realm name of the configured KDC.
 *   It does no have default value.</li>
 *   <li>kerberos.keytab: the keytab file containing the credentials for the kerberos principal.
 *   It does not have default value.</li>
 * </ul>
 */
public class KerberosAuthenticationHandler implements AuthenticationHandler {
    private static Logger LOG = LoggerFactory.getLogger(KerberosAuthenticationHandler.class);

    /**
     * Kerberos context configuration for the JDK GSS library.
     */
    private static class KerberosConfiguration extends Configuration {
        private String keytab;
        private String principal;

        public KerberosConfiguration(String keytab, String principal) {
            this.keytab = keytab;
            this.principal = principal;
        }

        @Override
        public AppConfigurationEntry[] getAppConfigurationEntry(String name) {
            Map<String, String> options = new HashMap<String, String>();
            options.put("keyTab", keytab);
            options.put("principal", principal);
            options.put("useKeyTab", "true");
            options.put("storeKey", "true");
            options.put("doNotPrompt", "true");
            options.put("useTicketCache", "true");
            options.put("renewTGT", "true");
            options.put("refreshKrb5Config", "true");
            options.put("isInitiator", "false");
            String ticketCache = System.getenv("KRB5CCNAME");
            if (ticketCache != null) {
                options.put("ticketCache", ticketCache);
            }
            if (LOG.isDebugEnabled()) {
                options.put("debug", "true");
            }

            return new AppConfigurationEntry[]{
                    new AppConfigurationEntry(Krb5LoginModule.class.getName(),
                                              AppConfigurationEntry.LoginModuleControlFlag.REQUIRED,
                                              options),};
        }
    }

    /**
     * Constant that identifies the authentication mechanism.
     */
    public static final String TYPE = "kerberos";

    /**
     * Constant for the configuration property that indicates the kerberos principal.
     */
    public static final String PRINCIPAL = "kerberos.principal";

    /**
     * Constant for the configuration property that indicates the keytab file path.
     */
    public static final String KEYTAB = "kerberos.keytab";

    private String principal;
    private String keytab;
    private GSSManager gssManager;
    private LoginContext loginContext;

    /**
     * Initializes the authentication handler instance.
     * <p/>
     * It creates a Kerberos context using the principal and keytab specified in the configuration.
     * <p/>
     * This method is invoked by the {@link AuthenticationFilter#init} method.
     *
     * @param config configuration properties to initialize the handler.
     *
     * @throws ServletException thrown if the handler could not be initialized.
     */
    @Override
    public void init(Properties config) throws ServletException {
        try {
            principal = config.getProperty(PRINCIPAL, principal);
            if (principal == null || principal.trim().length() == 0) {
                throw new ServletException("Principal not defined in configuration");
            }
            keytab = config.getProperty(KEYTAB, keytab);
            if (keytab == null || keytab.trim().length() == 0) {
                throw new ServletException("Keytab not defined in configuration");
            }
            if (!new File(keytab).exists()) {
                throw new ServletException("Keytab does not exist: " + keytab);
            }

            Set<Principal> principals = new HashSet<Principal>();
            principals.add(new KerberosPrincipal(principal));
            Subject subject = new Subject(false, principals, new HashSet<Object>(), new HashSet<Object>());

            KerberosConfiguration kerberosConfiguration = new KerberosConfiguration(keytab, principal);

            loginContext = new LoginContext("", subject, null, kerberosConfiguration);
            loginContext.login();

            Subject serverSubject = loginContext.getSubject();
            try {
                gssManager = Subject.doAs(serverSubject, new PrivilegedExceptionAction<GSSManager>() {

                    @Override
                    public GSSManager run() throws Exception {
                        return GSSManager.getInstance();
                    }
                });
            }
            catch (PrivilegedActionException ex) {
                throw ex.getException();
            }
            LOG.info("Initialized, principal [{}] from keytab [{}]", principal, keytab);
        }
        catch (Exception ex) {
            throw new ServletException(ex);
        }
    }

    /**
     * Releases any resources initialized by the authentication handler.
     * <p/>
     * It destroys the Kerberos context.
     */
    @Override
    public void destroy() {
        try {
            if (loginContext != null) {
                loginContext.logout();
            }
        }
        catch (LoginException ex) {
            LOG.warn(ex.getMessage(), ex);
        }
    }

    /**
     * Returns the Kerberos principal used by the authentication handler.
     *
     * @return the Kerberos principal used by the authentication handler.
     */
    protected String getPrincipal() {
        return principal;
    }

    /**
     * Returns the keytab used by the authentication handler.
     *
     * @return the keytab used by the authentication handler.
     */
    protected String getKeytab() {
        return keytab;
    }

    /**
     * It enforces the the Kerberos SPNEGO authentication sequence returning an {@link AuthenticationToken} only
     * after the Kerberos SPNEGO sequence completed successfully.
     * <p/>
     *
     * @param request the HTTP client request.
     * @param response the HTTP client response.
     * @return an authentication token if the Kerberos SPNEGO sequence is complete and valid,
     * <code>null</code> if is in progress (in this case the handler handles the response to the client).
     * @throws IOException thrown if an IO error occurred.
     * @throws AuthenticationException thrown if Kerberos SPNEGO sequence failed.
     */
    @Override
    public AuthenticationToken authenticate(HttpServletRequest request, final HttpServletResponse response)
            throws IOException, AuthenticationException {
        AuthenticationToken token = null;
        String authorization = request.getHeader(KerberosAuthenticator.AUTHORIZATION);

        if (authorization == null) {
            response.setHeader(KerberosAuthenticator.WWW_AUTHENTICATE, KerberosAuthenticator.NEGOTIATE);
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            LOG.trace("SPNEGO starts");
        }
        else if (!authorization.startsWith(KerberosAuthenticator.NEGOTIATE)) {
            response.setHeader(KerberosAuthenticator.WWW_AUTHENTICATE, KerberosAuthenticator.NEGOTIATE);
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            LOG.warn("'" + KerberosAuthenticator.AUTHORIZATION + "' does not start with '" +
                     KerberosAuthenticator.NEGOTIATE + "' :  {}", authorization);
        }
        else {
            authorization = authorization.substring(KerberosAuthenticator.NEGOTIATE.length()).trim();
            final Base64 base64 = new Base64(0);
            final byte[] clientToken = base64.decode(authorization);
            Subject serverSubject = loginContext.getSubject();
            try {
                token = Subject.doAs(serverSubject, new PrivilegedExceptionAction<AuthenticationToken>() {

                    @Override
                    public AuthenticationToken run() throws Exception {
                        AuthenticationToken token = null;
                        GSSContext gssContext = null;
                        try {
                            gssContext = gssManager.createContext((GSSCredential) null);
                            byte[] serverToken = gssContext.acceptSecContext(clientToken, 0, clientToken.length);
                            if (serverToken != null && serverToken.length > 0) {
                                String authenticate = base64.encodeToString(serverToken);
                                response.setHeader(KerberosAuthenticator.WWW_AUTHENTICATE,
                                                   KerberosAuthenticator.NEGOTIATE + " " + authenticate);
                            }
                            if (!gssContext.isEstablished()) {
                                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                                LOG.trace("SPNEGO in progress");
                            }
                            else {
                                String clientPrincipal = gssContext.getSrcName().toString();
                                int index = clientPrincipal.indexOf("/");
                                if (index == -1) {
                                    index = clientPrincipal.indexOf("@");
                                }
                                String userName = (index == -1) ? clientPrincipal : clientPrincipal.substring(0, index);
                                token = new AuthenticationToken(userName, clientPrincipal, TYPE);
                                response.setStatus(HttpServletResponse.SC_OK);
                                LOG.trace("SPNEGO completed for principal [{}]", clientPrincipal);
                            }
                        }
                        finally {
                            if (gssContext != null) {
                                gssContext.dispose();
                            }
                        }
                        return token;
                    }
                });
            }
            catch (PrivilegedActionException ex) {
                if (ex.getException() instanceof IOException) {
                    throw (IOException) ex.getException();
                }
                else {
                    throw new AuthenticationException(ex.getException());
                }
            }
        }
        return token;
    }

}
