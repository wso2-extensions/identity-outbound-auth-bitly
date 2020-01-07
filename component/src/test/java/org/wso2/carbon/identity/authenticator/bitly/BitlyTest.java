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
import java.net.URL;
import java.util.HashMap;
import java.util.Map;
import static org.mockito.MockitoAnnotations.initMocks;
import org.apache.oltu.oauth2.client.OAuthClient;
import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.client.response.OAuthAuthzResponse;
import org.apache.oltu.oauth2.client.response.OAuthClientResponse;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
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

public class BitlyTest {

    BitlyAuthenticator bitlyAuthenticator;

    @Mock
    private OAuthClientResponse oAuthClientResponse;

    @Mock
    private OAuthClient mockOAuthClient;

    @Mock
    private OAuthClientRequest mockOAuthClientRequest;

    @DataProvider(name = "authenticatorProperties")
    public Object[][] getAuthenticatorPropertiesData() {
        Map<String, String> authenticatorProperties = new HashMap<>();
        authenticatorProperties.put(OIDCAuthenticatorConstants.CLIENT_ID, "test-client-id");
        authenticatorProperties.put(OIDCAuthenticatorConstants.CLIENT_SECRET, "test-client-secret");
        authenticatorProperties.put("callbackUrl", "http://localhost:9443/commonauth");
        authenticatorProperties.put("tokenEndpoint", "https://api-ssl.bitly.com/oauth/access_token");
        authenticatorProperties.put("code", "dummy-code");
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
        OAuthClientRequest accessRequest = Whitebox.invokeMethod(bitlyAuthenticator, "getAccessRequest",
                authenticatorProperties.get("tokenEndpoint"), authenticatorProperties.get(OIDCAuthenticatorConstants.CLIENT_ID),
                authenticatorProperties.get("code"), authenticatorProperties.get(OIDCAuthenticatorConstants.CLIENT_SECRET),
                authenticatorProperties.get("callbackUrl"));
        Whitebox.invokeMethod(bitlyAuthenticator, "getOauthResponse", mockOAuthClient, mockOAuthClientRequest);
        Assert.assertNotNull(accessRequest);
    }

    @Test(description = "Test case for GetName")
    public void testGetName() {
        String name = bitlyAuthenticator.getName();
        Assert.assertEquals("bitly", name);
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
                "getOauthResponse", mockOAuthClient, mockOAuthClientRequest);
        Map<ClaimMapping, String> claims = Whitebox.invokeMethod(bitlyAuthenticator,
                "getSubjectAttributes", oAuthClientResponse,
                authenticatorProperties);
        Assert.assertEquals(0, claims.size());
    }
}

