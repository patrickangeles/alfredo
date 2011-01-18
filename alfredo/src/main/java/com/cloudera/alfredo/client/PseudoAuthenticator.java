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

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;

/**
 * The <code>PseudoAuthenticator</code> implementation provides an authentication equivalent to Hadoop
 * Simple authentication, it trust the value of the 'user.name' Java System property.
 * <p/>
 * The 'user.name' value is propagated using an additional query string parameter {@link #USER_NAME} ('user.name').
 *
 */
public class PseudoAuthenticator implements Authenticator {

    /**
     * Name of the additional parameter that carries the 'user.name' value.
     */
    public static final String USER_NAME = "user.name";

    private static final String USER_NAME_EQ = USER_NAME + "=";

    /**
     * Performs simple authentication against the specified URL.
     * <p/>
     * If a token is given if does a NOP and returns the given token.
     * <p/>
     * If no token is given, it will perform a HTTP <code>OPTIONS</code> request injecting an additional
     * parameter {@link #USER_NAME} in the query string with the value returned by the {@link #getUserName()}
     * method.
     * <p>
     * If the response is successful it will update the authentication token.
     *
     * @param url the URl to authenticate against.
     * @param token the authencation token being used for the user.
     * @throws IOException if an IO error occurred.
     * @throws AuthenticationException if an authentication error occurred.
     */
    @Override
    public void authenticate(URL url, AuthenticatedURL.Token token) throws IOException, AuthenticationException {
        String strUrl = url.toString();
        String paramSeparator = (strUrl.contains("?")) ? "&" : "?";
        strUrl += paramSeparator + USER_NAME_EQ + getUserName();
        url = new URL(strUrl);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("OPTIONS");
        conn.connect();
        AuthenticatedURL.extractToken(conn, token);
    }

    /**
     * Returns the current user name.
     * <p/>
     * This implementation returns the value of the Java system property 'user.name'
     * 
     * @return the current user name.
     */
    protected String getUserName() {
        return System.getProperty("user.name");
    }
}
