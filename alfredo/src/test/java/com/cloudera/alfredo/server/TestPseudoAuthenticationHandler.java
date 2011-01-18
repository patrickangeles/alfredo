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
import junit.framework.TestCase;
import com.cloudera.alfredo.client.PseudoAuthenticator;
import org.mockito.Mockito;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Properties;

/**
 *
 */
public class TestPseudoAuthenticationHandler extends TestCase {

    public void testInit() throws Exception {
        PseudoAuthenticationHandler handler = new PseudoAuthenticationHandler();
        try {
            Properties props = new Properties();
            props.setProperty(PseudoAuthenticationHandler.ANNONYMOUS_ALLOWED, "false");
            handler.init(props);
            assertEquals(false, handler.getAcceptAnnonymous());
        }
        finally {
            handler.destroy();
        }
    }

    public void testAnnonymousOn() throws Exception {
        PseudoAuthenticationHandler handler = new PseudoAuthenticationHandler();
        try {
            Properties props = new Properties();
            props.setProperty(PseudoAuthenticationHandler.ANNONYMOUS_ALLOWED, "true");
            handler.init(props);

            HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
            HttpServletResponse response = Mockito.mock(HttpServletResponse.class);

            AuthenticationToken token = handler.authenticate(request, response);

            assertEquals(AuthenticationToken.ANNONYMOUS, token);
        }
        finally {
            handler.destroy();
        }
    }

    public void testAnnonymousOff() throws Exception {
        PseudoAuthenticationHandler handler = new PseudoAuthenticationHandler();
        try {
            Properties props = new Properties();
            props.setProperty(PseudoAuthenticationHandler.ANNONYMOUS_ALLOWED, "false");
            handler.init(props);

            HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
            HttpServletResponse response = Mockito.mock(HttpServletResponse.class);

            handler.authenticate(request, response);
            fail();
        }
        catch (AuthenticationException ex) {
        }
        catch (Exception ex) {
            fail();
        }
        finally {
            handler.destroy();
        }
    }

    private void _testUserName(boolean annonymous) throws Exception {
        PseudoAuthenticationHandler handler = new PseudoAuthenticationHandler();
        try {
            Properties props = new Properties();
            props.setProperty(PseudoAuthenticationHandler.ANNONYMOUS_ALLOWED, Boolean.toString(annonymous));
            handler.init(props);

            HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
            HttpServletResponse response = Mockito.mock(HttpServletResponse.class);
            Mockito.when(request.getParameter(PseudoAuthenticator.USER_NAME)).thenReturn("user");

            AuthenticationToken token = handler.authenticate(request, response);
            
            assertNotNull(token);
            assertEquals("user", token.getUserName());
            assertEquals("user", token.getName());
            assertEquals(PseudoAuthenticationHandler.TYPE, token.getType());
        }
        finally {
            handler.destroy();
        }
    }

    public void testUserNameAnnonymousOff() throws Exception {
        _testUserName(false);
    }

    public void testUserNameAnnonymousOn() throws Exception {
        _testUserName(true);
    }
    
}
