package com.cloudera.alfredo.util;

import junit.framework.TestCase;

/**
 *
 */
public class TestSigner extends TestCase {

    public void testNoSecret() throws Exception {
        try {
            new Signer(null);
            fail();
        }
        catch (IllegalArgumentException ex) {
        }
    }

    public void testNullAndEmptyString() throws Exception {
        Signer signer = new Signer("secret".getBytes());
        try {
            signer.sign(null);
            fail();
        }
        catch (IllegalArgumentException ex) {
        }
        catch (Throwable ex) {
            fail();
        }
        try {
            signer.sign("");
            fail();
        }
        catch (IllegalArgumentException ex) {
        }
        catch (Throwable ex) {
            fail();
        }
    }

    public void testSignature() throws Exception {
        Signer signer = new Signer("secret".getBytes());
        String s1 = signer.sign("ok");
        String s2 = signer.sign("ok");
        String s3 = signer.sign("wrong");
        assertEquals(s1, s2);
        assertNotSame(s1, s3);
    }

    public void testVerify() throws Exception {
        Signer signer = new Signer("secret".getBytes());
        String t = "test";
        String s = signer.sign(t);
        String e = signer.verifyAndExtract(s);
        assertEquals(t, e);
    }

    public void testInvalidSignedText() throws Exception {
        Signer signer = new Signer("secret".getBytes());
        try {
            signer.verifyAndExtract("test");
            fail();
        }
        catch (SignerException ex) {
        }
        catch (Throwable ex) {
            fail();
        }
    }

    public void testTampering() throws Exception {
        Signer signer = new Signer("secret".getBytes());
        String t = "test";
        String s = signer.sign(t);
        s += "x";
        try {
            signer.verifyAndExtract(s);
            fail();
        }
        catch (SignerException ex) {
        }
        catch (Throwable ex) {
            fail();
        }
    }

}
