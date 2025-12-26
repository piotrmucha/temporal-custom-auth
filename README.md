# Temporal Custom Server with Keycloak RBAC

This repository features a custom **Temporal Server** distribution with an integrated **Authorizer** and **ClaimMapper**. It is designed to work with **Keycloak** to provide Role-Based Access Control (RBAC) via JWT tokens.

---

##  Purpose

The primary objective of this project is to demonstrate a custom authentication and authorization flow for Temporal:
* **Custom Claim Mapping**: Translates specialized fields in a Keycloak JWT into Temporal-specific roles.
* **Fine-Grained Authorization**: Implements a custom `Authorize` method to validate access at both the system and namespace levels.
* **OIDC Integration**: Configures the Temporal UI and Server to trust a local Keycloak instance as the Identity Provider (IdP).



---

##  Usage Instructions

To ensure the environment initializes correctly, you must start the services in two distinct phases.

### Phase 1: Start and Configure Keycloak
First, bring up the identity provider to set up the necessary authentication realm.

1.  **Run Keycloak**:
    ```bash
    docker compose -f temporal-docker-compose.yml up -d keycloak
    ```
2.  **Configure the Realm**:
    Access the admin console at `http://localhost:20080` (Credentials: `admin`/`admin`).
    * Create a realm named **`temporal`**.
    * **Crucial**: Follow [this article](INSERT_LINK_HERE) to configure the custom token mapper for the `custom` claim array.

### Phase 2: Start Temporal Infrastructure
Once Keycloak is ready, initialize the database and the custom Temporal server.

1.  **Run the full stack**:
    ```bash
    docker compose -f temporal-docker-compose.yml up -d --build
    ```
    * The `--build` flag ensures your custom logic in `main.go` is compiled into the server image[cite: 2, 3].

---

##  What to Expect

### Access URLs
| Component | URL |
| :--- | :--- |
| **Temporal UI** | `http://localhost:8089` |
| **Keycloak Admin** | `http://localhost:20080` |

### Authorization Logic
The server's custom `ClaimMapper` parses the `custom` field in your JWT to determine permissions:

* **System Admin**: Granted if the JWT contains `"admin"` in the custom array.
* **Namespace Reader**: Granted for the `default` namespace if the JWT contains `"only-default-read"`.
* **Access Denied**: Requests without a valid token or matching permissions will be rejected with an authorization error.