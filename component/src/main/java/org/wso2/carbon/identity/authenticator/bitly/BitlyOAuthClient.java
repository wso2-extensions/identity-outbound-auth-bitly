/*
 *  Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

import org.apache.oltu.oauth2.client.HttpClient;
import org.apache.oltu.oauth2.client.OAuthClient;
import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.client.response.OAuthAccessTokenResponse;
import org.apache.oltu.oauth2.common.OAuth;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;

import java.util.HashMap;
import java.util.Map;

/**
 * Set accept header OAuth request
 */
public class BitlyOAuthClient extends OAuthClient {

    public BitlyOAuthClient(HttpClient oauthClient) {
        super(oauthClient);
    }

    @Override
    public <T extends OAuthAccessTokenResponse> T accessToken(
            OAuthClientRequest request, String requestMethod, Class<T> responseClass)
            throws OAuthSystemException, OAuthProblemException {

        Map<String, String> headers = new HashMap<String, String>();
        headers.put(BitlyAuthenticatorConstants.ACCEPT_HEADER, OAuth.ContentType.JSON);

        return httpClient.execute(request, headers, requestMethod, responseClass);
    }
}
