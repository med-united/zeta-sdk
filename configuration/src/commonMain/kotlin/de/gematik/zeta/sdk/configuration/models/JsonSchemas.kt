/*
 * #%L
 * ZETA-Client
 * %%
 * (C) EY Strategy & Transactions GmbH, 2025, licensed for gematik GmbH
 * %%
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
 *
 * ******
 *
 * For additional notes and disclaimer from gematik and in case of changes by gematik find details in the "Readme" file.
 * #L%
 */

package de.gematik.zeta.sdk.configuration.models

val AUTHORIZATION_SERVER_SCHEMA_JSON = """
{
  "${'$'}schema" : "http://json-schema.org/draft-07/schema#",
  "type" : "object",
  "properties" : {
    "issuer" : {
      "type" : "string",
      "format" : "uri",
      "description" : "The URL of the issuer."
    },
    "authorization_endpoint" : {
      "type" : "string",
      "format" : "uri",
      "description" : "The URL of the authorization endpoint."
    },
    "token_endpoint" : {
      "type" : "string",
      "format" : "uri",
      "description" : "The URL of the token endpoint."
    },
    "nonce_endpoint" : {
      "type" : "string",
      "format" : "uri",
      "description" : "The URL of the nonce endpoint."
    },
    "openid_providers_endpoint" : {
      "type" : "string",
      "format" : "uri",
      "description" : "The URL of the openid providers endpoint."
    },
    "jwks_uri" : {
      "type" : "string",
      "format" : "uri",
      "description" : "The URL of the JSON Web Key Set."
    },
    "scopes_supported" : {
      "type" : "array",
      "description" : "The scopes supported by the authorization server.",
      "items" : {
        "type" : "string"
      }
    },
    "response_types_supported" : {
      "type" : "array",
      "description" : "The response types supported by the authorization server.",
      "items" : {
        "type" : "string",
        "enum" : [ "code", "token" ]
      }
    },
    "response_modes_supported" : {
      "type" : "array",
      "description" : "The response modes supported by the authorization server.",
      "items" : {
        "type" : "string"
      }
    },
    "grant_types_supported" : {
      "type" : "array",
      "description" : "The grant types supported by the authorization server.",
      "items" : {
        "type" : "string"
      }
    },
    "token_endpoint_auth_methods_supported" : {
      "type" : "array",
      "description" : "The token endpoint authentication methods supported.",
      "items" : {
        "type" : "string"
      }
    },
    "token_endpoint_auth_signing_alg_values_supported" : {
      "type" : "array",
      "description" : "The signing algorithms supported at the token endpoint.",
      "items" : {
        "type" : "string"
      }
    },
    "service_documentation" : {
      "type" : "string",
      "format" : "uri",
      "description" : "A URL to the service documentation."
    },
    "ui_locales_supported" : {
      "type" : "array",
      "description" : "The UI locales supported by the authorization server.",
      "items" : {
        "type" : "string"
      }
    },
    "code_challenge_methods_supported" : {
      "type" : "array",
      "description" : "The code challenge methods supported for PKCE.",
      "items" : {
        "type" : "string"
      }
    },
    "api_versions_supported" : {
      "type" : "array",
      "description" : "A JSON array listing the supported API versions for this protected resource.",
      "items" : {
        "type" : "object",
        "properties" : {
          "major_version" : {
            "type" : "integer",
            "description" : "The major version number of the API."
          },
          "version" : {
            "type" : "string",
            "description" : "The full, stable Semantic Versioning (SemVer) compliant string for this API version."
          },
          "status" : {
            "type" : "string",
            "description" : "The release status of this API version.",
            "enum" : [ "stable", "beta", "alpha", "deprecated", "retired" ]
          },
          "documentation_uri" : {
            "type" : "string",
            "format" : "uri",
            "description" : "URL of the documentation specific to this API version."
          }
        },
        "required" : [ "major_version", "version", "status" ]
      }
    }
  },
  "required" : [ "issuer", "authorization_endpoint", "nonce_endpoint", "openid_providers_endpoint", "token_endpoint", "jwks_uri", "scopes_supported", "response_types_supported", "grant_types_supported", "token_endpoint_auth_methods_supported", "token_endpoint_auth_signing_alg_values_supported", "ui_locales_supported", "code_challenge_methods_supported" ]
}
""".trimIndent()

val PROTECTED_RESOURCE_SCHEMA_JSON = """
{
  "${'$'}schema" : "http://json-schema.org/draft-07/schema#",
  "type" : "object",
  "properties" : {
    "resource" : {
      "type" : "string",
      "description" : "Identifier for the protected resource. This MUST be a URL using the `https` scheme and MUST NOT include a fragment component. It is RECOMMENDED that this URL does not include a query component, but using one is permitted if necessary for resource identification. (See [Reference to relevant spec, e.g., RFC XXXX Section 1.2] for the formal definition).",
      "format" : "uri"
    },
    "authorization_servers" : {
      "type" : "array",
      "description" : "A JSON array listing the Issuer Identifiers ([RFC8414]) of the OAuth Authorization Servers that can authorize access to this protected resource. The resource MAY omit some supported authorization servers from this list. If the set of supported authorization servers is not enumerable or discoverable via this mechanism, this parameter SHOULD be omitted.",
      "items" : {
        "type" : "string",
        "format" : "uri"
      }
    },
    "jwks_uri" : {
      "type" : "string",
      "description" : "URL of the protected resource's JSON Web Key Set (JWK Set) [RFC7517] document. This document contains public keys owned by the protected resource, potentially including keys used for signing resource responses (e.g., according to [Reference to FAPI Message Signing spec]). This URL MUST use the `https` scheme. If the JWK Set contains keys for both signing (`sig`) and encryption (`enc`), the `use` (public key use) parameter is REQUIRED for each key to declare its intended purpose.",
      "format" : "uri"
    },
    "scopes_supported" : {
      "type" : "array",
      "description" : "A JSON array listing the OAuth 2.0 [RFC6749] scope values supported by this protected resource for requesting access. The resource MAY omit some supported scope values from this list.",
      "items" : {
        "type" : "string"
      }
    },
    "bearer_methods_supported" : {
      "type" : "array",
      "description" : "A JSON array listing the methods supported by the protected resource for receiving OAuth 2.0 Bearer Tokens [RFC6750]. Valid values are `\"header\"`, `\"body\"`, and `\"query\"`, corresponding to Sections 2.1, 2.2, and 2.3 of RFC 6750, respectively. An empty array `[]` indicates that Bearer Tokens transmitted using these methods are not supported. Omission of this parameter implies no defaults and indicates nothing about supported methods.",
      "items" : {
        "type" : "string",
        "enum" : [ "header", "body", "query" ]
      }
    },
    "resource_signing_alg_values_supported" : {
      "type" : "array",
      "description" : "A JSON array listing the JWS [RFC7515] signing algorithms (`alg` values) [RFC7518] supported by the protected resource for signing its responses (e.g., as described in [Reference to FAPI Message Signing spec]). Omission of this parameter implies no default algorithms. The value `\"none\"` MUST NOT be included in this list.",
      "items" : {
        "type" : "string"
      }
    },
    "resource_name" : {
      "type" : "string",
      "description" : "A human-readable name for the protected resource, suitable for display to end-users. Inclusion of this field is RECOMMENDED. The value MAY be internationalized (e.g., using language tags as specified in [Reference to relevant spec, e.g., RFC XXXX Section 2.1])."
    },
    "resource_documentation" : {
      "type" : "string",
      "description" : "URL of a web page providing human-readable documentation for developers about using this protected resource. The target content MAY be internationalized (e.g., as specified in [Reference to relevant spec, e.g., RFC XXXX Section 2.1]).",
      "format" : "uri"
    },
    "resource_policy_uri" : {
      "type" : "string",
      "description" : "URL of a web page detailing the protected resource's policy regarding client usage of the data it provides. The target content MAY be internationalized (e.g., as specified in [Reference to relevant spec, e.g., RFC XXXX Section 2.1]).",
      "format" : "uri"
    },
    "resource_tos_uri" : {
      "type" : "string",
      "description" : "URL of a web page specifying the protected resource's terms of service. The target content MAY be internationalized (e.g., as specified in [Reference to relevant spec, e.g., RFC XXXX Section 2.1]).",
      "format" : "uri"
    },
    "tls_client_certificate_bound_access_tokens" : {
      "type" : "boolean",
      "description" : "Boolean value indicating whether the protected resource supports mutual-TLS client certificate-bound access tokens [RFC8705]. If omitted, the default value is `false`.",
      "default" : false
    },
    "authorization_details_types_supported" : {
      "type" : "array",
      "description" : "A JSON array listing the `type` values supported by the resource server for the `authorization_details` parameter defined in [RFC9396].",
      "items" : {
        "type" : "string"
      }
    },
    "dpop_signing_alg_values_supported" : {
      "type" : "array",
      "description" : "A JSON array listing the JWS `alg` values (from the IANA \"JSON Web Signature and Encryption Algorithms\" registry [IANA.JOSE]) supported by the resource server for validating DPoP proof JWTs [RFC9449].",
      "items" : {
        "type" : "string"
      }
    },
    "dpop_bound_access_tokens_required" : {
      "type" : "boolean",
      "description" : "Boolean value indicating whether the protected resource requires DPoP-bound access tokens [RFC9449] for all authorized requests. If omitted, the default value is `false`.",
      "default" : false
    },
    "signed_metadata" : {
      "type" : "string",
      "description" : "A JWT [RFC7519] containing metadata parameters about the protected resource as claims. The value is the JWT itself, represented as a string. This `signed_metadata` parameter itself SHOULD NOT appear as a claim within the signed JWT; metadata containing such a claim SHOULD be rejected."
    },
    "zeta_asl_use" : {
      "type" : "string",
      "description" : "Indicates whether and how the ZETA/ASL protocol is utilized by this resource server. `not_supported`: ZETA/ASL is not used or supported. `required`: ZETA/ASL is mandatory for interaction with this resource server.",
      "enum" : [ "not_supported", "required" ]
    },
    "api_versions_supported" : {
      "type" : "array",
      "description" : "A JSON array listing the supported API versions for this protected resource.",
      "items" : {
        "type" : "object",
        "properties" : {
          "major_version" : {
            "type" : "integer",
            "description" : "The major version number of the API."
          },
          "version" : {
            "type" : "string",
            "description" : "The full, stable Semantic Versioning (SemVer) compliant string for this API version."
          },
          "status" : {
            "type" : "string",
            "description" : "The release status of this API version.",
            "enum" : [ "stable", "beta", "alpha", "deprecated", "retired" ]
          },
          "documentation_uri" : {
            "type" : "string",
            "format" : "uri",
            "description" : "URL of the documentation specific to this API version."
          }
        },
        "required" : [ "major_version", "version", "status" ]
      }
    }
  },
  "required" : [ "resource", "authorization_servers", "zeta_asl_use" ]
}
""".trimIndent()
