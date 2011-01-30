Alfredo, Java HTTP SPNEGO

Alfredo is a Java library consisting of a client and a server components
to enable Kerberos SPNEGO authentication for HTTP.

Alfredo is distributed under Apache License 2.0.

The client component is the AuthenticatedURL class.

The server component is the AuthenticationFilter servlet filter class.

Authentication mechanisms support is pluggable in both the client and
the server components via interfaces.

In addition to Kerberos SPNEGO, Alfredo also supports Pseudo/Simple
authentication (trusting the value of the query string parameter
'user.name').

----------------------------------------------------------------------------
Documentation:

  http://cloudera.github.com/alfredo

----------------------------------------------------------------------------
Maven information:

  Group Id: com.cloudera.alfredo
  Artifact Id: alfredo
  Available Versions: 0.1.0, 0.1.1, 0.1.2, 0.1.3, 0.1.4
  Type: jar

  Repository: https://repository.cloudera.com/content/repositories/releases

----------------------------------------------------------------------------

If you have any questions/issues, please send an email to:

  cdh-user@cloudera.org

----------------------------------------------------------------------------

