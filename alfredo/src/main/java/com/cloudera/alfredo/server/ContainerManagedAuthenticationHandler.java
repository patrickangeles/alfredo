package com.cloudera.alfredo.server;

import java.io.IOException;
import java.security.Principal;
import java.util.Properties;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.cloudera.alfredo.client.AuthenticationException;

/**
 * The {@code ContainerManagedAuthenticationHandler} does no authentication. It
 * expects authentication to be managed by the servlet container through HTTP
 * authentication or other mechanism. The {@link AuthenticationToken} username
 * and principal are derived from the {@link Principal} returned by
 * {@link HttpServletRequest#getUserPrincipal()}.
 */
public class ContainerManagedAuthenticationHandler implements AuthenticationHandler {

    /**
     * Constant that identifies the authentication mechanism.
     */
    public static final String TYPE = "managed";

    /**
     * Initializes the authentication handler instance.
     * <p/>
     * This method is invoked by the {@link AuthenticationFilter#init} method.
     *
     * @param config configuration properties to initialize the handler.
     *
     * @throws ServletException thrown if the handler could not be initialized.
     */
    @Override
    public void init(Properties config) throws ServletException {
    }

    /**
     * Releases any resources initialized by the authentication handler.
     * <p/>
     * This implementation does a NOP.
     */
    @Override
    public void destroy() {
    }

    /**
   * Returns the authentication type of the authentication handler.
   * <p/>
   *
   * @return the authentication type of the authentication handler.
   */
    @Override
    public String getType() {
        return TYPE;
    }

    /**
   * Authenticates an HTTP client request.
   *
   * @param request the HTTP client request.
   * @param response the HTTP client response.
   * @return an authentication token.
   * @throws IOException thrown if an IO error occurred.
   * @throws AuthenticationException thrown if HTTP client request was not
   *           accepted as an authentication request.
   */
    @Override
    public AuthenticationToken authenticate(HttpServletRequest request, HttpServletResponse response)
            throws IOException, AuthenticationException {
      Principal principal = request.getUserPrincipal();
      if (principal == null) {
        throw new AuthenticationException("Authentication required.");
      }
      String userName = principal.getName();

      return new AuthenticationToken(userName, userName, TYPE);
    }

}
