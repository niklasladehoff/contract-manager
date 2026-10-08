package handler

import "net/http"

// SwaggerHandler serves OpenAPI documentation and Swagger UI.
type SwaggerHandler struct{}

// NewSwaggerHandler creates a new SwaggerHandler.
func NewSwaggerHandler() *SwaggerHandler {
	return &SwaggerHandler{}
}

// OpenAPISpec serves the backend OpenAPI specification as JSON.
func (h *SwaggerHandler) OpenAPISpec(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(openAPISpecJSON))
}

// UI serves a minimal Swagger UI page.
func (h *SwaggerHandler) UI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(swaggerUIHTML))
}

const swaggerUIHTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>IBM Confidential Computing Contract Generator API Docs</title>
  <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css" />
  <style>
    body { margin: 0; background: #fafafa; }
    #swagger-ui { max-width: 1200px; margin: 0 auto; }
  </style>
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
  <script>
    window.ui = SwaggerUIBundle({
      url: '/openapi.json',
      dom_id: '#swagger-ui',
      deepLinking: true,
      persistAuthorization: true
    });
  </script>
</body>
</html>`

const openAPISpecJSON = `{
  "openapi": "3.0.3",
  "info": {
    "title": "IBM Confidential Computing Contract Generator API",
    "version": "0.1.0",
    "description": "API for persona-based contract build orchestration."
  },
  "servers": [
    { "url": "/", "description": "Current server" }
  ],
  "components": {
    "securitySchemes": {
      "bearerAuth": {
        "type": "http",
        "scheme": "bearer",
        "bearerFormat": "API Token"
      }
    },
    "schemas": {
      "LoginRequest": {
        "type": "object",
        "required": ["email", "password"],
        "properties": {
          "email": { "type": "string", "format": "email" },
          "password": { "type": "string" }
        }
      },
      "CreateUserRequest": {
        "type": "object",
        "required": ["name", "email", "password", "roles"],
        "properties": {
          "name": { "type": "string" },
          "email": { "type": "string", "format": "email" },
          "password": { "type": "string" },
          "roles": {
            "type": "array",
            "items": { "type": "string" }
          }
        }
      },
      "CreateBuildRequest": {
        "type": "object",
        "required": ["name"],
        "properties": {
          "name": { "type": "string" }
        }
      },
      "TransitionStatusRequest": {
        "type": "object",
        "required": ["status"],
        "properties": {
          "status": { "type": "string" }
        }
      },
      "SubmitSectionRequest": {
        "type": "object",
        "required": ["persona_role", "encrypted_payload", "section_hash", "signature"],
        "properties": {
          "persona_role": { "type": "string" },
          "encrypted_payload": { "type": "string" },
          "encrypted_symmetric_key": { "type": "string", "nullable": true },
          "section_hash": { "type": "string" },
          "signature": { "type": "string" }
        }
      },
      "FinalizeBuildRequest": {
        "type": "object",
        "required": ["contract_hash", "contract_yaml", "signature", "public_key"],
        "properties": {
          "contract_hash": { "type": "string" },
          "contract_yaml": { "type": "string" },
          "signature": { "type": "string" },
          "public_key": { "type": "string" }
        }
      },
      "AttestationEvidenceUploadResponse": {
        "type": "object",
        "required": ["evidence_id", "build_id", "uploaded_by", "records_file_name", "signature_file_name", "created_at", "state"],
        "properties": {
          "evidence_id": { "type": "string", "format": "uuid" },
          "build_id": { "type": "string", "format": "uuid" },
          "uploaded_by": { "type": "string", "format": "uuid" },
          "records_file_name": { "type": "string" },
          "signature_file_name": { "type": "string" },
          "created_at": { "type": "string", "format": "date-time" },
          "state": { "type": "string", "enum": ["UPLOADED"] }
        }
      },
      "AttestationEvidenceVerificationResponse": {
        "type": "object",
        "required": ["verification_id", "evidence_id", "verdict", "state", "details", "verified_at"],
        "properties": {
          "verification_id": { "type": "string", "format": "uuid" },
          "evidence_id": { "type": "string", "format": "uuid" },
          "verdict": { "type": "string", "enum": ["VERIFIED", "REJECTED"] },
          "state": { "type": "string", "enum": ["VERIFIED", "REJECTED"] },
          "details": { "type": "object", "additionalProperties": true },
          "verified_at": { "type": "string", "format": "date-time" }
        }
      },
      "AttestationStatusResponse": {
        "type": "object",
        "required": ["build_id", "attestation_state", "evidence_count", "state"],
        "properties": {
          "build_id": { "type": "string", "format": "uuid" },
          "attestation_state": { "type": "string", "enum": ["PENDING_UPLOAD", "UPLOADED", "VERIFIED", "REJECTED"] },
          "evidence_count": { "type": "integer", "format": "int64", "minimum": 0 },
          "latest_verdict": { "type": "string", "enum": ["VERIFIED", "REJECTED"], "nullable": true },
          "verified_at": { "type": "string", "format": "date-time", "nullable": true },
          "verified_by": { "type": "string", "format": "uuid", "nullable": true },
          "last_result": { "type": "object", "additionalProperties": true },
          "state": { "type": "string", "enum": ["PENDING_UPLOAD", "UPLOADED", "VERIFIED", "REJECTED"] }
        }
      },
      "ErrorResponse": {
        "type": "object",
        "properties": {
          "error": {
            "type": "object",
            "properties": {
              "code": { "type": "string" },
              "message": { "type": "string" },
              "details": {}
            }
          }
        }
      }
    }
  },
  "paths": {
    "/health": {
      "get": {
        "summary": "Health check",
        "responses": {
          "200": { "description": "Server healthy" }
        }
      }
    },
    "/about": {
      "get": {
        "summary": "Get version and system information",
        "description": "Returns application version, backend version, contract-go version, OpenSSL version, and platform information",
        "responses": {
          "200": {
            "description": "Version information",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "app": {
                      "type": "object",
                      "properties": {
                        "version": { "type": "string", "example": "1.0.0" }
                      }
                    },
                    "backend": {
                      "type": "object",
                      "properties": {
                        "version": { "type": "string", "example": "1.0.0" },
                        "contract_go_version": { "type": "string", "example": "v2.19.0" },
                        "openssl_version": { "type": "string", "example": "3.0.2" },
                        "go_version": { "type": "string", "example": "go1.26.1" },
                        "platform": { "type": "string", "example": "linux/amd64" }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    },
    "/auth/login": {
      "post": {
        "summary": "Login",
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": { "$ref": "#/components/schemas/LoginRequest" }
            }
          }
        },
        "responses": {
          "200": { "description": "Login successful" },
          "401": {
            "description": "Invalid credentials",
            "content": {
              "application/json": {
                "schema": { "$ref": "#/components/schemas/ErrorResponse" }
              }
            }
          }
        }
      }
    },
    "/auth/logout": {
      "post": {
        "summary": "Logout",
        "security": [{ "bearerAuth": [] }],
        "responses": {
          "204": { "description": "Logged out" },
          "401": { "description": "Unauthorized" }
        }
      }
    },
    "/v2/contract-template": {
      "post": {
        "summary": "Get contract template",
        "description": "Returns a shared contract template generated by contract-go.",
        "security": [{ "bearerAuth": [] }],
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": {
                "type": "object",
                "required": ["type"],
                "properties": {
                  "type": {
                    "type": "string",
                    "enum": ["workload", "env"],
                    "description": "Contract template type"
                  }
                }
              }
            }
          }
        },
        "responses": {
          "200": {
            "description": "Template content",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "template_type": { "type": "string", "enum": ["workload", "env"] },
                    "content": { "type": "string" }
                  }
                }
              }
            }
          },
          "400": {
            "description": "Invalid template type",
            "content": {
              "application/json": {
                "schema": { "$ref": "#/components/schemas/ErrorResponse" }
              }
            }
          },
          "401": { "description": "Unauthorized" }
        }
      }
    },
    "/users": {
      "get": {
        "summary": "List users (ADMIN or AUDITOR)",
        "security": [{ "bearerAuth": [] }],
        "responses": {
          "200": { "description": "Users list" }
        }
      },
      "post": {
        "summary": "Create user (ADMIN)",
        "security": [{ "bearerAuth": [] }],
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": { "$ref": "#/components/schemas/CreateUserRequest" }
            }
          }
        },
        "responses": {
          "201": { "description": "User created" }
        }
      }
    },
    "/users/{id}/roles": {
      "patch": {
        "summary": "Replace user roles (ADMIN)",
        "security": [{ "bearerAuth": [] }],
        "parameters": [
          {
            "name": "id",
            "in": "path",
            "required": true,
            "schema": { "type": "string", "format": "uuid" }
          }
        ],
        "responses": {
          "200": { "description": "Roles updated" }
        }
      }
    },
    "/users/{id}/tokens": {
      "get": {
        "summary": "List API tokens (owner or ADMIN)",
        "security": [{ "bearerAuth": [] }],
        "parameters": [
          {
            "name": "id",
            "in": "path",
            "required": true,
            "schema": { "type": "string", "format": "uuid" }
          }
        ],
        "responses": {
          "200": { "description": "Tokens list" }
        }
      },
      "post": {
        "summary": "Create API token (owner or ADMIN)",
        "security": [{ "bearerAuth": [] }],
        "parameters": [
          {
            "name": "id",
            "in": "path",
            "required": true,
            "schema": { "type": "string", "format": "uuid" }
          }
        ],
        "responses": {
          "201": { "description": "Token created" }
        }
      }
    },
    "/users/{id}/tokens/{token_id}": {
      "delete": {
        "summary": "Revoke API token (owner or ADMIN)",
        "security": [{ "bearerAuth": [] }],
        "parameters": [
          {
            "name": "id",
            "in": "path",
            "required": true,
            "schema": { "type": "string", "format": "uuid" }
          },
          {
            "name": "token_id",
            "in": "path",
            "required": true,
            "schema": { "type": "string", "format": "uuid" }
          }
        ],
        "responses": {
          "204": { "description": "Token revoked" }
        }
      }
    },
    "/builds": {
      "get": {
        "summary": "List builds",
        "security": [{ "bearerAuth": [] }],
        "parameters": [
          {
            "name": "limit",
            "in": "query",
            "required": false,
            "schema": { "type": "integer", "minimum": 1, "maximum": 100 }
          },
          {
            "name": "offset",
            "in": "query",
            "required": false,
            "schema": { "type": "integer", "minimum": 0 }
          },
          {
            "name": "status",
            "in": "query",
            "required": false,
            "schema": { "type": "string" }
          }
        ],
        "responses": {
          "200": { "description": "Builds list" }
        }
      },
      "post": {
        "summary": "Create build (ADMIN or AUDITOR)",
        "security": [{ "bearerAuth": [] }],
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": { "$ref": "#/components/schemas/CreateBuildRequest" }
            }
          }
        },
        "responses": {
          "201": { "description": "Build created" }
        }
      }
    },
    "/builds/{id}": {
      "get": {
        "summary": "Get build",
        "security": [{ "bearerAuth": [] }],
        "parameters": [
          {
            "name": "id",
            "in": "path",
            "required": true,
            "schema": { "type": "string", "format": "uuid" }
          }
        ],
        "responses": {
          "200": { "description": "Build details" }
        }
      }
    },
    "/builds/{id}/status": {
      "patch": {
        "summary": "Transition build status",
        "security": [{ "bearerAuth": [] }],
        "parameters": [
          {
            "name": "id",
            "in": "path",
            "required": true,
            "schema": { "type": "string", "format": "uuid" }
          }
        ],
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": { "$ref": "#/components/schemas/TransitionStatusRequest" }
            }
          }
        },
        "responses": {
          "200": { "description": "Status updated" }
        }
      }
    },
    "/builds/{id}/finalize": {
      "post": {
        "summary": "Finalize build (AUDITOR)",
        "security": [{ "bearerAuth": [] }],
        "parameters": [
          {
            "name": "id",
            "in": "path",
            "required": true,
            "schema": { "type": "string", "format": "uuid" }
          }
        ],
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": { "$ref": "#/components/schemas/FinalizeBuildRequest" }
            }
          }
        },
        "responses": {
          "200": { "description": "Build finalized" }
        }
      }
    },
    "/builds/{id}/cancel": {
      "post": {
        "summary": "Cancel build (ADMIN or AUDITOR)",
        "security": [{ "bearerAuth": [] }],
        "parameters": [
          {
            "name": "id",
            "in": "path",
            "required": true,
            "schema": { "type": "string", "format": "uuid" }
          }
        ],
        "responses": {
          "200": { "description": "Build cancelled" }
        }
      }
    },
    "/builds/{id}/sections": {
      "get": {
        "summary": "List build sections",
        "security": [{ "bearerAuth": [] }],
        "parameters": [
          {
            "name": "id",
            "in": "path",
            "required": true,
            "schema": { "type": "string", "format": "uuid" }
          }
        ],
        "responses": {
          "200": { "description": "Sections list" }
        }
      },
      "post": {
        "summary": "Submit section",
        "security": [{ "bearerAuth": [] }],
        "parameters": [
          {
            "name": "id",
            "in": "path",
            "required": true,
            "schema": { "type": "string", "format": "uuid" }
          }
        ],
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": { "$ref": "#/components/schemas/SubmitSectionRequest" }
            }
          }
        },
        "responses": {
          "201": { "description": "Section submitted" }
        }
      }
    },
    "/builds/{id}/audit-trail": {
      "get": {
        "summary": "Get build audit trail",
        "security": [{ "bearerAuth": [] }],
        "parameters": [
          {
            "name": "id",
            "in": "path",
            "required": true,
            "schema": { "type": "string", "format": "uuid" }
          }
        ],
        "responses": {
          "200": { "description": "Audit events list" }
        }
      }
    },
    "/builds/{id}/attestation/evidence": {
      "post": {
        "summary": "Upload attestation evidence",
        "description": "Lifecycle constraint: allowed only when build status is FINALIZED or CONTRACT_DOWNLOADED and attestation_state is PENDING_UPLOAD or REJECTED. Upload transitions attestation_state to UPLOADED.",
        "security": [{ "bearerAuth": [] }],
        "parameters": [
          {
            "name": "id",
            "in": "path",
            "required": true,
            "schema": { "type": "string", "format": "uuid" }
          }
        ],
        "requestBody": {
          "required": true,
          "content": {
            "multipart/form-data": {
              "schema": {
                "type": "object",
                "required": ["records_file", "signature_file"],
                "properties": {
                  "records_file": { "type": "string", "format": "binary" },
                  "signature_file": { "type": "string", "format": "binary" }
                }
              }
            }
          }
        },
        "responses": {
          "201": {
            "description": "Evidence uploaded",
            "content": {
              "application/json": {
                "schema": { "$ref": "#/components/schemas/AttestationEvidenceUploadResponse" }
              }
            }
          },
          "400": { "description": "Lifecycle/state preconditions not satisfied or invalid multipart payload" },
          "403": { "description": "Only assigned DATA_OWNER or ENV_OPERATOR can upload evidence" }
        }
      }
    },
    "/builds/{id}/attestation/evidence/{evidence_id}/verify": {
      "post": {
        "summary": "Verify attestation evidence (AUDITOR)",
        "description": "Lifecycle constraint: allowed only when build status is FINALIZED or CONTRACT_DOWNLOADED and attestation_state is UPLOADED. Verification transitions state to VERIFIED or REJECTED.",
        "security": [{ "bearerAuth": [] }],
        "parameters": [
          {
            "name": "id",
            "in": "path",
            "required": true,
            "schema": { "type": "string", "format": "uuid" }
          },
          {
            "name": "evidence_id",
            "in": "path",
            "required": true,
            "schema": { "type": "string", "format": "uuid" }
          }
        ],
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": {
                "type": "object",
                "required": ["attestation_certificate_pem"],
                "properties": {
                  "attestation_key_passphrase": {
                    "type": "string",
                    "description": "Passphrase for decrypting an encrypted attestation private key, if applicable."
                  },
                  "attestation_certificate_pem": {
                    "type": "string",
                    "description": "PEM-encoded IBM attestation certificate used to verify the attestation records signature."
                  }
                }
              }
            }
          }
        },
        "responses": {
          "200": {
            "description": "Evidence verified",
            "content": {
              "application/json": {
                "schema": { "$ref": "#/components/schemas/AttestationEvidenceVerificationResponse" }
              }
            }
          },
          "400": { "description": "Lifecycle/state preconditions not satisfied or invalid evidence" },
          "403": { "description": "Only assigned AUDITOR can verify evidence" }
        }
      }
    },
    "/builds/{id}/attestation/status": {
      "get": {
        "summary": "Get attestation verification status",
        "description": "Returns attestation_state, evidence_count, latest_verdict, and latest verification result metadata for the build.",
        "security": [{ "bearerAuth": [] }],
        "parameters": [
          {
            "name": "id",
            "in": "path",
            "required": true,
            "schema": { "type": "string", "format": "uuid" }
          }
        ],
        "responses": {
          "200": {
            "description": "Attestation status",
            "content": {
              "application/json": {
                "schema": { "$ref": "#/components/schemas/AttestationStatusResponse" }
              }
            }
          }
        }
      }
    }
  }
}`
