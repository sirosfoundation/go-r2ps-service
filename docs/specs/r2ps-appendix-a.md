# Appendix A: Service Type Creation Framework

## A.1. Introduction

This framework enables deployments to create custom service types.

Each service type MUST define:

1. Its service type identifier (the value of `type`).
2. The schema of the request and response `data` objects.
3. Its message-exchange mode (`1FA` or `2FA`).

A server that receives a service request under an exchange mode other than the one declared by the specified service type MUST reject the request.

## A.2. Extensibility

Additional service types SHOULD be defined as profiles of this document, each satisfying the three requirements above. Identifiers SHOULD be namespaced to avoid collision across profiles. The EUDIW service types in §6 are such a profile, namespaced under `eudiw_`.

## A.3. Defining a Service Type

Every service type MUST follow the template in this section. A service type definition is a completed instance of this template.

Service types fall into two classes:

* **Application service types** Execute over an established `2FA` session or within `1FA` mode.
* **Second-factor lifecycle types**: Establish, prove, or modify a second factor. The core service types are of this class; new types of this class are expected to be rare.

### A.3.1. Elements

A service type definition MUST specify:

* **Identifier**: The value of the `type` request parameter. Identifiers MUST be namespaced to the defining profile (e.g., `eudiw_…`) to prevent collisions across profiles.
* **Mode**: The exchange mode. A service type operating on a hardware-protected private key MUST be `2FA`; otherwise, it MUST be `1FA`.
* **Request `data` structure**: The members of the request `data` object, specifying the name, data type, and requirement status (required or optional) of each member.
* **Response `data` structure**: The members of the response `data` object.

A service type definition MUST also specify, where applicable:

* **State values**: For multi-round exchanges, the definition MUST enumerate the valid `state` values and the content carried in each.

A service type definition SHOULD include a worked example and MAY include additional information relevant to the service type.

### A.3.2. Registration

A profile defining new service types SHOULD list their identifiers, modes, and defining section in a table and SHOULD record the namespace prefix it uses. The following table illustrates this format using the three core service types:

|     Identifier     |              Purpose                           |  Mode  |
|--------------------|------------------------------------------------|--------|
| `2fa_registration` | Establishes a new second factor                | `1FA`  |
| `2fa_authenticate` | Verifies the second factor and opens a session | `1FA`  |
| `2fa_change`       | Replaces an existing second factor             | `2FA`  |


### A.3.3.  Service Type Definition Template (non-normative)

Instantiate and complete the following template for each new service type definition.

#### \<Service type name\>

* Identifier: `<prefix>_<name>`
* Mode: `1FA` | `2FA`
* State values: Single-round or enumerates the valid state values for multi-round exchanges.

Purpose: \<Describe functionality\>

Request `data` schema:

* `<field>` (`<type>`, required | optional): \<Description\>.

Response `data` schema:

* `<field>` (`<type>`, required | optional): \<description\>.

**Worked Example**

Request payload:

```json
{
  "ver": "1.0",
  "nonce": "<nonce>",
  "iat": 0,
  "data": {},
  "client_id": "https://example.com/wallet/1",
  "context": "<context>",
  "type": "<prefix>_<name>"
}
```

Response payload:

```json
{
  "ver": "1.0",
  "nonce": "<echoed nonce>",
  "iat": 0,
  "data": {}
}
```
**Additional information**: 

* Security Considerations: \<Security considerations service specific this to type\>.
* Rejection Conditions: \<Type-specific and conditions\ failure validation\>.
