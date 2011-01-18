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

/**
 *
 */
public class TestAuthenticationToken extends TestCase {

    public void testAnnonymous() {
        assertNotNull(AuthenticationToken.ANNONYMOUS);
        assertEquals(null, AuthenticationToken.ANNONYMOUS.getUserName());
        assertEquals(null, AuthenticationToken.ANNONYMOUS.getName());
        assertEquals(null, AuthenticationToken.ANNONYMOUS.getType());
        assertEquals(-1, AuthenticationToken.ANNONYMOUS.getExpires());
        assertFalse(AuthenticationToken.ANNONYMOUS.isExpired());
    }

    public void testConstructor() throws Exception {
        try {
            new AuthenticationToken(null, "p", "t");
            fail();
        }
        catch (IllegalArgumentException ex) {
        }
        catch (Throwable ex) {
            fail();
        }
        try {
            new AuthenticationToken("", "p", "t");
            fail();
        }
        catch (IllegalArgumentException ex) {
        }
        catch (Throwable ex) {
            fail();
        }
        try {
            new AuthenticationToken("u", null, "t");
            fail();
        }
        catch (IllegalArgumentException ex) {
        }
        catch (Throwable ex) {
            fail();
        }
        try {
            new AuthenticationToken("u", "", "t");
            fail();
        }
        catch (IllegalArgumentException ex) {
        }
        catch (Throwable ex) {
            fail();
        }
        try {
            new AuthenticationToken("u", "p", null);
            fail();
        }
        catch (IllegalArgumentException ex) {
        }
        catch (Throwable ex) {
            fail();
        }
        try {
            new AuthenticationToken("u", "p", "");
            fail();
        }
        catch (IllegalArgumentException ex) {
        }
        catch (Throwable ex) {
            fail();
        }
        new AuthenticationToken("u", "p", "t");
    }

    public void testGetters() throws Exception {
        long expires = System.currentTimeMillis() + 50;
        AuthenticationToken token = new AuthenticationToken("u", "p", "t");
        token.setExpires(expires);
        assertEquals("u", token.getUserName());
        assertEquals("p", token.getName());
        assertEquals("t", token.getType());
        assertEquals(expires, token.getExpires());
        assertFalse(token.isExpired());
        Thread.sleep(51);
        assertTrue(token.isExpired());
    }

    public void testToStringAndParse() throws Exception {
        long expires = System.currentTimeMillis() + 50;
        AuthenticationToken token = new AuthenticationToken("u", "p", "t");
        token.setExpires(expires);
        String str = token.toString();
        token = AuthenticationToken.parse(str);
        assertEquals("p", token.getName());
        assertEquals("t", token.getType());
        assertEquals(expires, token.getExpires());
        assertFalse(token.isExpired());
        Thread.sleep(51);
        assertTrue(token.isExpired());        
    }

    public void testParseInvalid() throws Exception {
        long expires = System.currentTimeMillis() + 50;
        AuthenticationToken token = new AuthenticationToken("u", "p", "t");
        token.setExpires(expires);
        String str = token.toString();
        str = str.substring(0, str.indexOf("e="));
        try {
            AuthenticationToken.parse(str);
            fail();
        }
        catch (AuthenticationException ex) {
        }
        catch (Exception ex) {
            fail();
        }
    }
}
