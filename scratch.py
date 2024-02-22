from collections import Counter
import re

data = """
  CVE-2023-33695 - cn.hutool:hutool-core - CWE-377,CWE-732 - Insecure Temporary File in HuTool
  CVE-2023-50164 - org.apache.struts:struts2-core - CWE-552 - Apache Struts vulnerable to path traversal
  CVE-2022-23712 - org.elasticsearch:elasticsearch - CWE-754 - Improper Check for Unusual or Exceptional Conditions in Elasticsearch
  CVE-2022-41828 - com.amazon.redshift:redshift-jdbc42 - CWE-704 - com.amazon.redshift:redshift-jdbc42 vulnerable to remote command execution
  CVE-2022-22885 - cn.hutool:hutool-http - CWE-295 - Improper Certificate Validation in Hutool
  CVE-2022-3143 - org.wildfly.security:wildfly-elytron - CWE-203,CWE-208 - Wildfly-elytron possibly vulnerable to timing attacks via use of unsafe comparator
  CVE-2019-10091 - org.apache.geode:geode-core - CWE-295 - Apache Geode SSL endpoint verification vulnerability
  CVE-2023-6394 - io.quarkus:quarkus-smallrye-graphql-client - CWE-696,CWE-862 - Authorization bypass in Quarkus
  CVE-2023-44794 - cn.dev33:sa-token-core - CWE-281 - SaToken privilege escalation vulnerability
  CVE-2023-41835 - org.apache.struts:struts2-core - CWE-459 - Apache Struts Improper Control of Dynamically-Managed Code Resources vulnerability
  CVE-2022-34169 - xalan:xalan - CWE-681 - Apache Xalan Java XSLT library integer truncation issue when processing malicious XSLT stylesheets
  CVE-2020-1731 - org.keycloak:keycloak-core - CWE-330,CWE-341 - Predictable password in Keycloak
  CVE-2020-5529 - net.sourceforge.htmlunit:htmlunit - CWE-665 - Code execution vulnerability in HtmlUnit
  CVE-2022-31193 - org.dspace:dspace-jspui - CWE-601 - JSPUI's controlled vocabulary feature vulnerable to Open Redirect before v6.4 and v5.11
  CVE-2022-36364 - org.apache.calcite.avatica:avatica-core - CWE-665 - Apache Calcite Avatica JDBC driver arbitrary code execution
  CVE-2019-0233 - org.apache.struts:struts2-core - CWE-281 - Improper Preservation of Permissions in Apache Struts
  CVE-2023-4918 - org.keycloak:keycloak-core - CWE-256,CWE-319 - Keycloak vulnerable to Plaintext Storage of User Password
  CVE-2021-30129 - org.apache.sshd:sshd-mina - CWE-772 - Buffer Overflow in Apache Mina SSHD
  CVE-2019-0212 - org.apache.hbase:hbase - CWE-285 - Improper Authorization in org.apache.hbase:hbase
  CVE-2020-8022 - org.apache.tomcat:tomcat - CWE-276 - Incorrect Default Permissions in Apache Tomcat
  CVE-2023-44981 - org.apache.zookeeper:zookeeper - CWE-639 - Authorization Bypass Through User-Controlled Key vulnerability in Apache ZooKeeper
  CVE-2019-14379 - com.fasterxml.jackson.core:jackson-databind - CWE-1321,CWE-915 - Deserialization of untrusted data in FasterXML jackson-databind
  CVE-2020-1953 - org.apache.commons:commons-configuration2 - CWE-20 - Remote code execution in Apache Commons Configuration
  CVE-2019-17195 - com.nimbusds:nimbus-jose-jwt - CWE-754,CWE-755 - Improper Check for Unusual or Exceptional Conditions in Connect2id Nimbus JOSE+JWT
  CVE-2023-34034 - org.springframework.security:spring-security-config - CWE-284 - Access Control Bypass in Spring Security
  CVE-2019-10170 - org.keycloak:keycloak-core - CWE-267 - Privilege Defined With Unsafe Actions in Keycloak
  CVE-2019-10249 - org.eclipse.xtext:org.eclipse.xtext - CWE-319 - Potentially compromised builds
  CVE-2020-15170 - com.ctrip.framework.apollo:apollo-core - CWE-20 - Potential access control security issue in apollo-adminservice
  CVE-2019-7611 - org.elasticsearch:elasticsearch - CWE-284 - Improper Access Control in Elasticsearch
  CVE-2019-17352 - com.jfinal:jfinal - CWE-434 - JFinal file validation vulnerability
  CVE-2021-29479 - io.ratpack:ratpack-core - CWE-807 - Cached redirect poisoning via X-Forwarded-Host header
  CVE-2019-16869 - io.netty:netty-all - CWE-444 - HTTP Request Smuggling in Netty
  CVE-2022-23181 - org.apache.tomcat:tomcat - CWE-367 - Race condition in Apache Tomcat
  CVE-2021-36161 - org.apache.dubbo:dubbo - CWE-134 - Remote Code Execution in Apache Dubbo
  CVE-2019-11777 - org.eclipse.paho:org.eclipse.paho.client.mqttv3 - CWE-346,CWE-755 - Improper Handling of Exceptional Conditions and Origin Validation Error in Eclipse Paho Java client library
  CVE-2020-27826 - org.keycloak:keycloak-core - CWE-250 - Authentication Bypass in keycloak
  CVE-2019-17638 - org.eclipse.jetty:jetty-server - CWE-672,CWE-675 - Operation on a Resource after Expiration or Release in Jetty Server
  CVE-2020-28052 - org.bouncycastle:bcprov-jdk15to18 - CWE-670 - Logic error in Legion of the Bouncy Castle BC Java
  CVE-2019-11405 - org.openapitools:openapi-generator - CWE-311 - OpenAPI Tools OpenAPI Generator uses HTTP in various files
  CVE-2022-22968 - org.springframework:spring-core - CWE-178 - Improper handling of case sensitivity in Spring Framework
  CVE-2020-13934 - org.apache.tomcat:tomcat - CWE-119,CWE-476 - Improper Restriction of Operations within the Bounds of a Memory Buffer in Apache Tomcat
  CVE-2020-1963 - org.apache.ignite:ignite-core - CWE-862 - File system access via H2 in Apache Ignite
  CVE-2023-4759 - org.eclipse.jgit:org.eclipse.jgit - CWE-178 - Arbitrary File Overwrite in Eclipse JGit
  CVE-2021-40660 - org.javadelight:delight-nashorn-sandbox - CWE-1333 - Regular expression denial of service in Delight Nashorn Sandbox
  CVE-2020-7622 - io.jooby:jooby-netty - CWE-444 - Improper Neutralization of CRLF Sequences in HTTP Headers in Jooby ('HTTP Response Splitting)
  CVE-2021-30639 - org.apache.tomcat:tomcat - CWE-755 - Improper Handling of Exceptional Conditions in Apache Tomcat
  CVE-2020-11050 - org.java-websocket:Java-WebSocket - CWE-295,CWE-297 - Improper Validation of Certificate with Host Mismatch in Java-WebSocket
  CVE-2019-0231 - org.apache.mina:mina-core - CWE-319 - Cleartext Transmission of Sensitive Information in Apache MINA
  CVE-2019-10072 - org.apache.tomcat.embed:tomcat-embed-core - CWE-667 - Improper Locking in Apache Tomcat
  CVE-2019-10071 - org.apache.tapestry:tapestry-core - CWE-203,CWE-697 - Timing attack on HMAC signature comparison in Apache Tapestry
  CVE-2023-1428 - io.grpc:grpc-protobuf - CWE-617 - gRPC Reachable Assertion issue
  CVE-2021-42340 - org.apache.tomcat:tomcat - CWE-772 - Missing Release of Resource after Effective Lifetime in Apache Tomcat
  CVE-2020-7238 - io.netty:netty-handler - CWE-444 - HTTP Request Smuggling in Netty
  CVE-2023-33265 - com.hazelcast:hazelcast - CWE-862 - Hazelcast Executor Services don't check client permissions properly
  CVE-2023-31582 - org.bitbucket.b_c:jose4j - CWE-327,CWE-331 - jose4j uses weak cryptographic algorithm
  CVE-2020-1714 - org.keycloak:keycloak-core - CWE-20 - Improper Input Validation in Keycloak
  CVE-2021-26291 - org.apache.maven:maven-compat - CWE-346 - Origin Validation Error in Apache Maven
  CVE-2021-20202 - org.keycloak:keycloak-core - CWE-377 - Temporary Directory Hijacking Vulnerability in Keycloak
  CVE-2021-45105 - org.apache.logging.log4j:log4j-core - CWE-20,CWE-674 - Apache Log4j2 vulnerable to Improper Input Validation and Uncontrolled Recursion
  CVE-2023-1370 - net.minidev:json-smart - CWE-674 - json-smart Uncontrolled Recursion vulnerabilty
  CVE-2019-20444 - io.netty:netty-codec-http - CWE-444 - HTTP Request Smuggling in Netty
  CVE-2019-10184 - io.undertow:undertow-servlet - CWE-862 - Undertow Missing Authorization when requesting a protected directory without trailing slash
  CVE-2021-23900 - com.mikesamuel:json-sanitizer - CWE-248 - Uncaught Exception leading to Denial of Service in json-sanitizer
  CVE-2020-1695 - org.jboss.resteasy:resteasy-client - CWE-20 - Improper Input Validation in RESTEasy
  CVE-2019-12409 - org.apache.solr:solr-core - CWE-434 - Unrestricted upload of file with dangerous type in Apache Solr
  CVE-2023-1436 - org.codehaus.jettison:jettison - CWE-674 - Jettison vulnerable to infinite recursion
  CVE-2023-2422 - org.keycloak:keycloak-services - CWE-295 - Keycloak vulnerable to Improper Client Certificate Validation for OAuth/OpenID clients
  CVE-2019-12728 - org.grails:grails-core - CWE-494,CWE-669 - Incorrect Resource Transfer Between Spheres in Grails
  CVE-2020-7611 - io.micronaut:micronaut-http-client - CWE-444 - Micronaut's HTTP client is vulnerable to HTTP Request Header Injection
  CVE-2020-1745 - io.undertow:undertow-core - CWE-285 - Improper Authorization in Undertoe
  CVE-2019-10099 - org.apache.spark:spark-core_2.11 - CWE-312 - Sensitive data written to disk unencrypted in Spark
  CVE-2020-5403 - io.projectreactor.netty:reactor-netty-http - CWE-20,CWE-755 - Improper Handling of Exceptional Conditions and Improper Input Validation in Reactor Netty
  CVE-2019-14837 - org.keycloak:keycloak-core - CWE-547,CWE-798 - keycloak vulnerable to unauthorized login via mail server setup
  CVE-2021-23937 - org.apache.wicket:wicket-core - CWE-20 - DNS based denial of service in Apache Wicket
  CVE-2019-0230 - org.apache.struts:struts2-core - CWE-1321,CWE-915 - Improperly Controlled Modification of Dynamically-Determined Object Attributes in Apache Struts
  CVE-2023-46589 - org.apache.tomcat:tomcat-catalina - CWE-20,CWE-444 - Apache Tomcat Improper Input Validation vulnerability
  CVE-2022-42252 - org.apache.tomcat:tomcat - CWE-20,CWE-444 - Apache Tomcat may reject request containing invalid Content-Length header
  CVE-2023-40743 - org.apache.axis:axis - CWE-20 - Apache Axis 1.x (EOL) may allow RCE when untrusted input is passed to getService
  CVE-2019-10174 - org.infinispan:infinispan-core - CWE-470 - Use of Externally-Controlled Input to Select Classes or Code in Infinispan
  CVE-2023-36478 - org.eclipse.jetty.http2:http2-hpack - CWE-190 - HTTP/2 HPACK integer overflow and buffer allocation
  CVE-2022-23496 - nl.basjes.parse.useragent:yauaa - CWE-755 - Yauaa vulnerable to ArrayIndexOutOfBoundsException triggered by a crafted Sec-Ch-Ua-Full-Version-List
  CVE-2021-36090 - org.apache.commons:commons-compress - CWE-130 - Improper Handling of Length Parameter Inconsistency in Compress
  CVE-2022-25867 - io.socket:socket.io-client - CWE-476 - Socket.IO-client Java before 2.0.1 vulnerable to NULL Pointer Dereference
  CVE-2019-0223 - org.apache.qpid:proton-j - CWE-295 - Improper Certificate Validation in Apache Qpid Proton
  CVE-2023-6291 - org.keycloak:keycloak-services - CWE-20 - The redirect_uri validation logic allows for bypassing explicitly allowed hosts that would otherwise be restricted
  CVE-2020-17516 - org.apache.cassandra:cassandra-all - CWE-290 - Authentication Bypass in Apache Cassandra
  CVE-2019-3888 - io.undertow:undertow-core - CWE-532 - Credential exposure through log files in Undertow
  CVE-2021-42575 - com.googlecode.owasp-java-html-sanitizer:owasp-java-html-sanitizer - CWE-20 - Policies not properly enforced in OWASP Java HTML Sanitizer
  CVE-2019-10212 - io.undertow:undertow-core - CWE-532 - Potential to access user credentials from the log files when debug logging enabled
  CVE-2021-22569 - com.google.protobuf:protobuf-java - CWE-696 - A potential Denial of Service issue in protobuf-java
  CVE-2022-4147 - io.quarkus:quarkus-vertx-http - CWE-285 - Quarkus CORS filter allows simple GET and POST requests with an invalid Origin to proceed
  CVE-2022-41853 - org.hsqldb:hsqldb - CWE-470 - HyperSQL DataBase vulnerable to remote code execution when processing untrusted input
  CVE-2022-45046 - org.apache.camel:camel-ldap - CWE-90 - camel-ldap component allows LDAP Injection when using the filter option
"""

# Extract CWE-XXX using regular expression
cwe_ids = re.findall(r'CWE-\d+', data)

# Count occurrences of each unique CWE-ID
cwe_counts = Counter(cwe_ids)

# Print the counts
for cwe_id, count in cwe_counts.items():
    print(f"{cwe_id}: {count}")
