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
import static org.fcrepo.auth.webac.URIConstants.WEBAC_ACCESS_CONTROL_VALUE;
import static org.fcrepo.kernel.api.RdfLexicon.DC_NAMESPACE;

import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import org.fcrepo.integration.http.api.AbstractResourceIT;

import org.apache.commons.codec.binary.Base64;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPatch;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.message.AbstractHttpMessage;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.entity.InputStreamEntity;
import org.apache.http.entity.StringEntity;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author Peter Eichman
 * @author whikloj
 * @since September 4, 2015
 */
public class WebACRecipesIT extends AbstractResourceIT {

    private static final Logger logger = LoggerFactory.getLogger(WebACRecipesIT.class);

    private static final String DC_TITLE = DC_NAMESPACE + "title";

    /**
     * Convenience method to create an ACL with 0 or more authorization resources in the respository.
     */
    private String ingestAcl(final String username, final String aclResourcePath,
            final String... authorizationResourcePaths) throws IOException {

        // create the ACL
        final HttpResponse aclResponse = ingestTurtleResource(username, aclResourcePath, "/rest");

        // get the URI to the newly created resource
        final String aclURI = aclResponse.getFirstHeader("Location").getValue();

        // add all the authorizations
        for (final String authorizationResourcePath : authorizationResourcePaths) {
            ingestTurtleResource(username, authorizationResourcePath, aclURI.replace(serverAddress, ""));
        }

        return aclURI;
    }

    /**
     * Convenience method to POST the contents of a Turtle file to the repository to create a new resource. Returns
     * the HTTP response from that request. Throws an IOException if the server responds with anything other than a
     * 201 Created response code.
     */
    private HttpResponse ingestTurtleResource(final String username, final String path, final String requestURI)
            throws IOException {
        final HttpPost request = postObjMethod(requestURI);

        logger.debug("POST to {} to create {}", requestURI, path);

        setAuth(request, username);

        final InputStream file = this.getClass().getResourceAsStream(path);
        final InputStreamEntity fileEntity = new InputStreamEntity(file);
        request.setEntity(fileEntity);
        request.setHeader("Content-Type", "text/turtle;charset=UTF-8");

        try (final CloseableHttpResponse response = execute(request)) {
            assertEquals("Didn't get a CREATED response!", CREATED.getStatusCode(), getStatus(response));
            return response;
        }

    }

    /**
     * Convenience method to set up a regular FedoraResource
     *
     * @param path Path to put the resource under
     * @return the Location of the newly created resource
     * @throws IOException
     */
    private String ingestObj(final String path) throws IOException {
        final HttpPut request = putObjMethod(path.replace(serverAddress, ""));
        setAuth(request, "fedoraAdmin");
        try (final CloseableHttpResponse response = execute(request)) {
            assertEquals(HttpStatus.SC_CREATED, response.getStatusLine().getStatusCode());
            return response.getFirstHeader("Location").getValue();
        }
    }

    /**
     * Convenience method to link a Resource to a WebACL resource
     *
     * @param protectedResource path of the resource to be protected by the
     * @param aclResource path of the Acl resource
     * @throws UnsupportedEncodingException
     */
    private void linkToAcl(final String protectedResource, final String aclResource)
            throws IOException {
        final HttpPatch request = patchObjMethod(protectedResource.replace(serverAddress, ""));
        setAuth(request, "fedoraAdmin");
        request.setHeader("Content-type", "application/sparql-update");
        request.setEntity(new StringEntity(
                "INSERT { <> <" + WEBAC_ACCESS_CONTROL_VALUE + "> <" + aclResource + "> . } WHERE {}"));
        try (final CloseableHttpResponse response = execute(request)) {
            assertEquals(HttpStatus.SC_NO_CONTENT, response.getStatusLine().getStatusCode());
        }
    }

    /**
     * Convenience method for applying credentials to a request
     *
     * @param method the request to add the credentials to
     * @param username the username to add
     */
    private static void setAuth(final AbstractHttpMessage method, final String username) {
        final String creds = username + ":password";
        final String encCreds = new String(Base64.encodeBase64(creds.getBytes()));
        final String basic = "Basic " + encCreds;
        method.setHeader("Authorization", basic);
    }

    @Test
    public void scenario1() throws IOException {
        final String testObj = ingestObj("/rest/webacl_box1");
        final String acl1 = ingestAcl("fedoraAdmin", "/acls/01/acl.ttl", "/acls/01/authorization.ttl");
        linkToAcl(testObj, acl1);

        logger.debug("Anonymous can't read");
        final HttpGet request = getObjMethod(testObj.replace(serverAddress, ""));
        try (final CloseableHttpResponse response = execute(request)) {
            assertEquals(HttpStatus.SC_FORBIDDEN, getStatus(response));
        }

        logger.debug("Can username 'smith123' read " + testObj);
        setAuth(request, "smith123");
        try (final CloseableHttpResponse response = execute(request)) {
            assertEquals(HttpStatus.SC_OK, getStatus(response));
        }
    }

    @Test
    public void scenario2() throws IOException {
        final String testObj = ingestObj("/rest/box/bag/collection");
        final String acl2 = ingestAcl("fedoraAdmin", "/acls/02/acl.ttl", "/acls/02/authorization.ttl");
        linkToAcl(testObj, acl2);

        logger.debug("Anonymous can not read " + testObj);
        final HttpGet request = getObjMethod(testObj.replace(serverAddress, ""));
        try (final CloseableHttpResponse response = execute(request)) {
            assertEquals(HttpStatus.SC_FORBIDDEN, getStatus(response));
        }

        logger.debug("GroupId 'Editors' can read " + testObj);
        setAuth(request, "Editors");
        try (final CloseableHttpResponse response = execute(request)) {
            assertEquals(HttpStatus.SC_OK, getStatus(response));
        }

        logger.debug("Anonymous cannot write " + testObj);
        final HttpPatch patch = patchObjMethod(testObj.replace(serverAddress, ""));
        patch.setEntity(new StringEntity("INSERT { <> <" + DC_TITLE + "> \"Test title\" . } WHERE {}"));
        patch.setHeader("Content-type", "application/sparql-update");
        try (final CloseableHttpResponse response = execute(patch)) {
            assertEquals(HttpStatus.SC_FORBIDDEN, getStatus(response));
        }

        logger.debug("Editors can write " + testObj);
        setAuth(patch, "Editors");
        try (final CloseableHttpResponse response = execute(patch)) {
            assertEquals(HttpStatus.SC_NO_CONTENT, getStatus(response));
        }

    }

    @Test
    public void scenario3() throws IOException {
        final String testObj = ingestObj("/rest/dark/archive");
        final String testObj2 = ingestObj("/rest/dark/archive/sunshine");
        final String acl3 =
                ingestAcl("fedoraAdmin", "/acls/03/acl.ttl", "/acls/03/auth_open.ttl", "/acls/03/auth_restricted.ttl");
        linkToAcl(testObj, acl3);

        logger.debug("Anonymous can't read " + testObj);
        final HttpGet request1 = getObjMethod(testObj.replace(serverAddress, ""));
        try (final CloseableHttpResponse response = execute(request1)) {
            assertEquals(HttpStatus.SC_FORBIDDEN, getStatus(response));
        }

        logger.debug("Restricted can read " + testObj);
        setAuth(request1, "Restricted");
        try (final CloseableHttpResponse response = execute(request1)) {
            assertEquals(HttpStatus.SC_OK, getStatus(response));
        }

        logger.debug("Anonymous can read " + testObj2);
        final HttpGet request2 = getObjMethod(testObj2.replace(serverAddress, ""));
        try (final CloseableHttpResponse response = execute(request1)) {
            assertEquals(HttpStatus.SC_OK, getStatus(response));
        }

        logger.debug("Restricted can read " + testObj2);
        setAuth(request2, "Restricted");
        try (final CloseableHttpResponse response = execute(request1)) {
            assertEquals(HttpStatus.SC_OK, getStatus(response));
        }
    }

    @Test
    public void scenario4() throws IOException {
        final String testObj = ingestObj("/rest/public_collection");
        final String acl4 = ingestAcl("fedoraAdmin", "/acls/04/acl.ttl", "/acls/04/auth1.ttl", "/acls/04/auth2.ttl");
        linkToAcl(testObj, acl4);

        logger.debug("Anonymous can read " + testObj);
        final HttpGet request = getObjMethod(testObj.replace(serverAddress, ""));
        try (final CloseableHttpResponse response = execute(request)) {
            assertEquals(HttpStatus.SC_OK, getStatus(response));
        }

        logger.debug("Editors can read " + testObj);
        setAuth(request, "Editors");
        try (final CloseableHttpResponse response = execute(request)) {
            assertEquals(HttpStatus.SC_OK, getStatus(response));
        }

        logger.debug("Smith can access " + testObj);
        final HttpGet request2 = getObjMethod(testObj.replace(serverAddress, ""));
        setAuth(request2, "smith");
        try (final CloseableHttpResponse response = execute(request2)) {
            assertEquals(HttpStatus.SC_OK, getStatus(response));
        }

        logger.debug("Anonymous can't write " + testObj);
        final HttpPatch patch = patchObjMethod(testObj.replace(serverAddress, ""));
        patch.setHeader("Content-type", "application/sparql-update");
        patch.setEntity(new StringEntity("INSERT { <> <" + DC_TITLE + "> \"Change title\" . } WHERE {}"));
        try (final CloseableHttpResponse response = execute(patch)) {
            assertEquals(HttpStatus.SC_FORBIDDEN, getStatus(response));
        }

        logger.debug("Editors can write " + testObj);
        setAuth(patch, "Editors");
        try (final CloseableHttpResponse response = execute(patch)) {
            assertEquals(HttpStatus.SC_NO_CONTENT, getStatus(response));
        }

        logger.debug("Smith can't write " + testObj);
        final HttpPatch patch2 = patchObjMethod(testObj.replace(serverAddress, ""));
        patch2.setHeader("Content-type", "application/sparql-update");
        patch2.setEntity(new StringEntity("INSERT { <> <" + DC_TITLE + "> \"Change title\" . } WHERE {}"));
        setAuth(patch2, "smith");
        try (final CloseableHttpResponse response = execute(patch2)) {
            assertEquals(HttpStatus.SC_FORBIDDEN, getStatus(response));
        }

    }

    @Test
    public void scenario5() throws IOException {
        final String testObj = ingestObj("/rest/mixedCollection");
        final String publicObj = ingestObj("/rest/mixedCollection/publicObj");
        final HttpPatch patch = patchObjMethod("/rest/mixedCollection/publicObj");
        final String acl5 =
                ingestAcl("fedoraAdmin", "/acls/05/acl.ttl", "/acls/05/auth_open.ttl", "/acls/05/auth_restricted.ttl");
        linkToAcl(testObj, acl5);

        setAuth(patch, "fedoraAdmin");
        patch.setHeader("Content-type", "application/sparql-update");
        patch.setEntity(new StringEntity("INSERT { <> a <http://example.com/terms#publicImage> . } WHERE {}"));
        try (final CloseableHttpResponse response = execute(patch)) {
            assertEquals(HttpStatus.SC_NO_CONTENT, getStatus(response));
        }
        final String privateObj = ingestObj("/rest/mixedCollection/privateObj");

        logger.debug("Anonymous can see eg:publicImage " + publicObj);
        final HttpGet request1 = getObjMethod(publicObj.replace(serverAddress, ""));
        try (final CloseableHttpResponse response = execute(request1)) {
            assertEquals(HttpStatus.SC_OK, getStatus(response));
        }

        logger.debug("Anonymous can't see other resource " + privateObj);
        final HttpGet request2 = getObjMethod(privateObj.replace(serverAddress, ""));
        try (final CloseableHttpResponse response = execute(request2)) {
            assertEquals(HttpStatus.SC_FORBIDDEN, getStatus(response));
        }

        logger.debug("Admins can see eg:publicImage " + publicObj);
        setAuth(request1, "Admins");
        try (final CloseableHttpResponse response = execute(request1)) {
            assertEquals(HttpStatus.SC_OK, getStatus(response));
        }

        logger.debug("Admins can see others" + privateObj);
        setAuth(request2, "Admins");
        try (final CloseableHttpResponse response = execute(request2)) {
            assertEquals(HttpStatus.SC_OK, getStatus(response));
        }

    }
}
