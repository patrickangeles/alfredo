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
package com.cloudera.alfredo.client;

import com.cloudera.alfredo.server.AuthenticationFilter;
import com.cloudera.alfredo.server.PseudoAuthenticationHandler;

import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Properties;

/**
 *
 */
public class TestPseudoAuthenticator extends AuthenticatorTestCase {

    private Properties getAuthenticationHandlerConfiguration(boolean annonymousAllowed) {
        Properties props = new Properties();
        props.setProperty(AuthenticationFilter.AUTH_TYPE, "simple");
        props.setProperty(PseudoAuthenticationHandler.ANNONYMOUS_ALLOWED, Boolean.toString(annonymousAllowed));
        return props;
    }

    public void testGetUserName() throws Exception {
        PseudoAuthenticator authenticator = new PseudoAuthenticator();
        assertEquals(System.getProperty("user.name"), authenticator.getUserName());
    }
    
    public void testAnnonymousAllowed() throws Exception {
        setAuthenticationHandlerConfig(getAuthenticationHandlerConfiguration(true));
        start();
        try {
            URL url = new URL(getBaseURL());
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.connect();
            assertEquals(HttpURLConnection.HTTP_OK, conn.getResponseCode());
        }
        finally {
            stop();
        }
    }

    public void testAnnonymousDisallowed() throws Exception {
        setAuthenticationHandlerConfig(getAuthenticationHandlerConfiguration(false));
        start();
        try {
            URL url = new URL(getBaseURL());
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.connect();
            assertEquals(HttpURLConnection.HTTP_UNAUTHORIZED, conn.getResponseCode());
        }
        finally {
            stop();
        }
    }

    public void testAuthenticationAnnonymousAllowed() throws Exception {
        setAuthenticationHandlerConfig(getAuthenticationHandlerConfiguration(true));
        _testAuthentication(new PseudoAuthenticator(), false);
    }

    public void testAuthenticationAnnonymousDisallowed() throws Exception {
        setAuthenticationHandlerConfig(getAuthenticationHandlerConfiguration(false));
        _testAuthentication(new PseudoAuthenticator(), false);
    }
    
    public void testAuthenticationAnnonymousAllowedWithPost() throws Exception {
        setAuthenticationHandlerConfig(getAuthenticationHandlerConfiguration(true));
        _testAuthentication(new PseudoAuthenticator(), true);
    }

    public void testAuthenticationAnnonymousDisallowedWithPost() throws Exception {
        setAuthenticationHandlerConfig(getAuthenticationHandlerConfiguration(false));
        _testAuthentication(new PseudoAuthenticator(), true);
    }

}
