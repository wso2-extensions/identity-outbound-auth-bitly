/*
 *  Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 *
 */

package org.wso2.carbon.identity.authenticator.bitly;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;

import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.spy;
import static org.mockito.MockitoAnnotations.initMocks;
import static org.powermock.api.mockito.PowerMockito.doReturn;
import static org.powermock.api.mockito.PowerMockito.mock;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.powermock.api.mockito.PowerMockito.whenNew;
import static org.testng.Assert.assertTrue;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.oltu.oauth2.client.OAuthClient;
import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.client.response.OAuthAuthzResponse;
import org.apache.oltu.oauth2.client.response.OAuthClientResponse;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.powermock.modules.testng.PowerMockTestCase;
import org.powermock.reflect.Whitebox;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;

@RunWith(PowerMockRunner.class)

@PrepareForTest({AuthenticatedUser.class, OAuthAuthzResponse.class,
        OAuthClientRequest.class, URL.class, OAuthClient.class})

public class BitlyTest extends PowerMockTestCase {

    BitlyAuthenticator bitlyAuthenticator;

    @Mock
    private OAuthClientResponse oAuthClientResponse;

    @Mock
    private OAuthClient mockOAuthClient;

    @Mock
    private OAuthClientRequest mockOAuthClientRequest;

    @Mock
    private HttpURLConnection mockConnection;

    private static String accessToken = "4952b467-86b2-31df-b63c-0bf25cec4f86s";
    private static String sendRequestResponse = "{\"created\":\"2022-07-26T06:54:34+0000\"," +
            "\"modified\":\"2022-07-26T06:54:34+0000\",\"login\":\"testUser\",\"is_active\":true," +
            "\"is_2fa_enabled\":false,\"name\":\"testUser\",\"emails\":[{\"email\":\"testUser@gmail.com\"," +
            "\"is_primary\":true,\"is_verified\":true}],\"is_sso_user\":false,\"default_group_guid\":\"abcdef\"}";

    @DataProvider(name = "authenticatorProperties")
    public Object[][] getAuthenticatorPropertiesData() {

        Map<String, String> authenticatorProperties = new HashMap<>();
        authenticatorProperties.put(OIDCAuthenticatorConstants.CLIENT_ID, "test-client-id");
        authenticatorProperties.put(OIDCAuthenticatorConstants.CLIENT_SECRET, "test-client-secret");
        authenticatorProperties.put(BitlyAuthenticatorConstants.CALLBACK_URL, "http://localhost:9443/commonauth");
        authenticatorProperties.put(BitlyAuthenticatorConstants.TOKEN_ENDPOINT,
                "https://api-ssl.bitly.com/oauth/access_token");
        authenticatorProperties.put(BitlyAuthenticatorConstants.CODE, "dummy-code");
        return new Object[][]{{authenticatorProperties}};
    }

    @BeforeMethod
    public void setUp() {
        bitlyAuthenticator = new BitlyAuthenticator();
        initMocks(this);
    }

    @Test(description = "Test case for GetConfigurationProperties")
    public void testGetConfigurationProperties() {

        Assert.assertEquals(IdentityApplicationConstants.OAuth2.CALLBACK_URL,
                bitlyAuthenticator.getConfigurationProperties().get(2).getName());
        Assert.assertEquals(3, bitlyAuthenticator.getConfigurationProperties().size());
    }

    @Test(description = "Test case for getAccessRequest", dataProvider = "authenticatorProperties")
    public void testGetAccessRequest(Map<String, String> authenticatorProperties) throws Exception {

        OAuthClientRequest accessRequest = Whitebox.invokeMethod(bitlyAuthenticator,
                BitlyAuthenticatorConstants.GET_ACCESS_REQUEST,
                authenticatorProperties.get(BitlyAuthenticatorConstants.TOKEN_ENDPOINT),
                authenticatorProperties.get(OIDCAuthenticatorConstants.CLIENT_ID),
                authenticatorProperties.get(BitlyAuthenticatorConstants.CODE),
                authenticatorProperties.get(OIDCAuthenticatorConstants.CLIENT_SECRET),
                authenticatorProperties.get(BitlyAuthenticatorConstants.CALLBACK_URL));
        Whitebox.invokeMethod(bitlyAuthenticator, BitlyAuthenticatorConstants.GET_OAUTH_RESPONSE,
                mockOAuthClient, mockOAuthClientRequest);
        Assert.assertNotNull(accessRequest);
    }

    @Test(description = "Test case for GetName")
    public void testGetName() {

        String name = bitlyAuthenticator.getName();
        Assert.assertEquals(BitlyAuthenticatorConstants.AUTHENTICATOR_NAME, name);
    }

    @Test(description = "Test case for GetFriendlyName")
    public void testGetFriendlyName() {

        Assert.assertEquals(BitlyAuthenticatorConstants.AUTHENTICATOR_FRIENDLY_NAME,
                bitlyAuthenticator.getFriendlyName());
    }

    @Test(description = "Test case for GetUserInfoEndpoint", dataProvider = "authenticatorProperties")
    public void testGetUserInfoEndpoint(Map<String, String> authenticatorProperties) {

        Assert.assertEquals(BitlyAuthenticatorConstants.BITLY_USERINFO_ENDPOINT,
                bitlyAuthenticator.getUserInfoEndpoint(oAuthClientResponse, authenticatorProperties));
    }

    @Test(description = "Test case for RequiredIDToken", dataProvider = "authenticatorProperties")
    public void testRequiredIDToken(Map<String, String> authenticatorProperties) {

        Assert.assertFalse(bitlyAuthenticator.requiredIDToken(authenticatorProperties));
    }

    @Test(description = "Test case for getAuthorizationServerEndpoint", dataProvider = "authenticatorProperties")
    public void testGetAuthorizationServerEndpoint(Map<String, String> authenticatorProperties) {

        Assert.assertEquals(BitlyAuthenticatorConstants.BITLY_OAUTH_ENDPOINT, bitlyAuthenticator.
                getAuthorizationServerEndpoint(authenticatorProperties));
    }

    @Test(description = "Test case for getSubjectAttributes", dataProvider = "authenticatorProperties")
    public void testGetSubjectAttributes(Map<String, String> authenticatorProperties) throws Exception {

        OAuthClientResponse oAuthClientResponse = Whitebox.invokeMethod(bitlyAuthenticator,
                BitlyAuthenticatorConstants.GET_OAUTH_RESPONSE, mockOAuthClient, mockOAuthClientRequest);
        Map<ClaimMapping, String> claims = Whitebox.invokeMethod(bitlyAuthenticator,
                BitlyAuthenticatorConstants.GET_SUBJECT_ATTRIBUTES, oAuthClientResponse, authenticatorProperties);
        Assert.assertEquals(0, claims.size());
    }

    @Test(description = "Test case for getSubjectAttributes", dataProvider = "authenticatorProperties")
    public void testGetSubjectAttributesPositive(Map<String, String> authenticatorProperties) throws Exception {

        when(oAuthClientResponse.getParam(anyString())).thenReturn(accessToken);
        bitlyAuthenticator = spy(BitlyAuthenticator.class);
        doReturn(sendRequestResponse).when(bitlyAuthenticator).sendRequest(anyString(), anyString());

        Map<ClaimMapping, String> claims = Whitebox.invokeMethod(bitlyAuthenticator,
                BitlyAuthenticatorConstants.GET_SUBJECT_ATTRIBUTES, oAuthClientResponse, authenticatorProperties);
        Assert.assertEquals(9, claims.size());
    }

    @Test
    public void testSendRequest() throws Exception {

        // InputStream is null.
        String result = bitlyAuthenticator.sendRequest(null, accessToken);
        assertTrue(StringUtils.isBlank(result), "The send request should be empty.");

        // InputStream is not null.
        InputStream stream =
                IOUtils.toInputStream("Some test data for my input stream", "UTF-8");

        URL url = mock(URL.class);
        whenNew(URL.class).withParameterTypes(String.class)
                .withArguments(anyString()).thenReturn(url);
        when(url.openConnection()).thenReturn(mockConnection);
        when(mockConnection.getInputStream()).thenReturn(stream);
        result = bitlyAuthenticator.sendRequest("https://www.google.com", accessToken);
        assertTrue(!result.isEmpty(), "The send request should not be empty.");
    }
}

