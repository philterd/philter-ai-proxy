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

import software.amazon.awssdk.identity.spi.AwsCredentialsIdentity;

import java.io.IOException;

/**
 * The credentials the proxy itself holds for cloud providers that do not take the client's: Vertex AI, Azure
 * OpenAI with Entra ID, and Bedrock. Each is read from the cloud's standard credential chain when first needed.
 */
public interface CloudCredentials {

    /** A Google OAuth access token with the cloud-platform scope, from application default credentials. */
    String googleAccessToken() throws IOException;

    /** An Entra ID access token for Azure Cognitive Services, from the default Azure credential chain. */
    String azureAccessToken() throws IOException;

    /** AWS credentials from the default chain, assuming {@code roleArn} when it is set. */
    AwsCredentialsIdentity awsCredentials(String region, String roleArn) throws IOException;

}
