/*
 *     Copyright 2026 Philterd, LLC @ https://www.philterd.ai
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *          http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ai.philterd.aiproxy.providers;

import com.azure.core.credential.AccessToken;
import com.azure.core.credential.TokenRequestContext;
import com.azure.identity.DefaultAzureCredential;
import com.azure.identity.DefaultAzureCredentialBuilder;
import com.google.auth.oauth2.GoogleCredentials;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.identity.spi.AwsCredentialsIdentity;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.sts.StsClient;
import software.amazon.awssdk.services.sts.auth.StsAssumeRoleCredentialsProvider;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/** Reads each cloud's standard credential chain on first use and refreshes tokens before they expire. */
@Component
public class DefaultCloudCredentials implements CloudCredentials {

    static final String GOOGLE_SCOPE = "https://www.googleapis.com/auth/cloud-platform";
    static final String AZURE_SCOPE = "https://cognitiveservices.azure.com/.default";

    private GoogleCredentials google;
    private DefaultAzureCredential azure;
    private AccessToken azureToken;
    private final Map<String, AwsCredentialsProvider> aws = new ConcurrentHashMap<>();

    @Override
    public synchronized String googleAccessToken() throws IOException {
        if (google == null) {
            google = GoogleCredentials.getApplicationDefault().createScoped(List.of(GOOGLE_SCOPE));
        }
        google.refreshIfExpired();
        return google.getAccessToken().getTokenValue();
    }

    @Override
    public synchronized String azureAccessToken() throws IOException {
        if (azureToken != null && azureToken.getExpiresAt().isAfter(OffsetDateTime.now().plusMinutes(5))) {
            return azureToken.getToken();
        }
        try {
            if (azure == null) {
                azure = new DefaultAzureCredentialBuilder().build();
            }
            azureToken = azure.getTokenSync(new TokenRequestContext().addScopes(AZURE_SCOPE));
            return azureToken.getToken();
        } catch (final RuntimeException e) {
            throw new IOException("Unable to get an Entra ID token: " + e.getMessage(), e);
        }
    }

    @Override
    public AwsCredentialsIdentity awsCredentials(final String region, final String roleArn) throws IOException {
        try {
            final AwsCredentialsProvider provider = aws.computeIfAbsent(roleArn == null ? "" : roleArn, role -> role.isEmpty()
                    ? DefaultCredentialsProvider.builder().build()
                    : StsAssumeRoleCredentialsProvider.builder()
                    .stsClient(StsClient.builder().region(Region.of(region)).build())
                    .refreshRequest(r -> r.roleArn(role).roleSessionName("philter-ai-proxy"))
                    .build());
            return provider.resolveCredentials();
        } catch (final RuntimeException e) {
            throw new IOException("Unable to get AWS credentials: " + e.getMessage(), e);
        }
    }

}
