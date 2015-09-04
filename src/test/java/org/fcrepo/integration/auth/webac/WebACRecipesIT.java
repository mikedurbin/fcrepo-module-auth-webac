/**
 * Copyright 2015 DuraSpace, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.fcrepo.integration.auth.webac;

import static javax.ws.rs.core.Response.Status.CREATED;
import static org.junit.Assert.assertEquals;
import static org.slf4j.LoggerFactory.getLogger;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.UUID;
import org.fcrepo.integration.http.api.AbstractResourceIT;

import org.apache.commons.codec.binary.Base64;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.entity.FileEntity;
import org.apache.http.message.AbstractHttpMessage;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.entity.InputStreamEntity;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;

/**
 * @author Peter Eichman
 * @author whikloj
 * @since September 4, 2015
 */
public class WebACRecipesIT extends AbstractResourceIT {

    private static Logger logger = getLogger(WebACRecipesIT.class);

    private final ClassLoader classLoader = getClass().getClassLoader();

    @Before
    public void setUp() throws IOException {
        final String credentials = "username:password";

        logger.debug("setting up ACLs and authorization rules");

        ingestAcl(credentials, "/acls/01/acl.ttl", "/acls/01/authorization.ttl");
        ingestAcl(credentials, "/acls/02/acl.ttl", "/acls/02/authorization.ttl");
        ingestAcl(credentials, "/acls/03/acl.ttl", "/acls/03/auth_open.ttl", "/acls/03/auth_restricted.ttl");
        ingestAcl(credentials, "/acls/04/acl.ttl", "/acls/04/auth1.ttl", "/acls/04/auth2.ttl");
        ingestAcl(credentials, "/acls/05/acl.ttl", "/acls/05/auth_open.ttl", "/acls/05/auth_restricted.ttl");

        logger.debug("setup complete");
    }

    @Test
    public void scenario1() throws Exception {
        logger.info("Running scenario1");
        final String objA = getRandomPid();
        final HttpPut method = super.putObjMethod("rest/" + objA);
        final FileEntity acl = new FileEntity(new File(classLoader.getResource("acls/01/acl.ttl").getFile()));
        setAuth(method, "fedoraAdmin");
        method.setHeader("Content-type", "text/turtle");
        method.setEntity(acl);
        try (final CloseableHttpResponse response = super.execute(method)) {
            assertEquals(CREATED.getStatusCode(), super.getStatus(response));
        }
    }

    protected static void setAuth(final AbstractHttpMessage method, final String username) {
        final String creds = username + ":password";
    }

    /**
     * Convenience method to create an ACL with 0 or more authorization resources in the respository.
     */
    private String ingestAcl(final String credentials, final String aclResourcePath,
            final String... authorizationResourcePaths) throws ClientProtocolException, IOException {

        // create the ACL
        final HttpResponse aclResponse = ingestTurtleResource(credentials, aclResourcePath, serverAddress);
        System.err.println(aclResponse.getStatusLine());

        // get the URI to the newly created resource
        final String aclURI = aclResponse.getFirstHeader("Location").getValue();

        // add all the authorizations
        for (final String authorizationResourcePath : authorizationResourcePaths) {
            final HttpResponse authzResponse = ingestTurtleResource(credentials, authorizationResourcePath, aclURI);
            System.err.println(authzResponse.getStatusLine());
        }

        return aclURI;
    }

    /**
     * Convenience method to POST the contents of a Turtle file to the repository to create a new resource. Returns
     * the HTTP response from that request. Throws an IOException if the server responds with anything other than a
     * 201 Created response code.
     */
    private HttpResponse ingestTurtleResource(final String credentials, final String path, final String requestURI)
            throws IOException {
        final HttpPut postRequest = new HttpPut(requestURI);

        final String message = "POST to " + requestURI + " to create " + path;
        logger.debug(message);

        // in test configuration we don't need real passwords
        final String encCreds = new String(Base64.encodeBase64(credentials.getBytes()));
        final String basic = "Basic " + encCreds;
        postRequest.setHeader("Authorization", basic);

        final InputStream file = this.getClass().getResourceAsStream(path);
        final InputStreamEntity fileEntity = new InputStreamEntity(file);
        postRequest.setEntity(fileEntity);
        postRequest.setHeader("Content-Type", "text/turtle;charset=UTF-8");

        // XXX: this is currently failing in the test repository with a
        // "java.lang.VerifyError: Bad type on operand stack"
        // see https://gist.github.com/peichman-umd/7f2eb8833ef8cd0cdfc1#gistcomment-1566271
        final HttpResponse response = client.execute(postRequest);
        Assert.assertEquals(HttpStatus.SC_CREATED, response.getStatusLine().getStatusCode());

        return response;
    }

    protected static String getRandomPid() {
        return UUID.randomUUID().toString();
    }
}
