Schema Validation
=================

* [Default Behavior](#default-behavior)
* [What Gets Validated](#what-gets-validated)
* [Entry Requirements](#entry-requirements)
    * [extensibleObject](#extensibleobject)
* [Validation Mode](#validation-mode)
    * [ServerOptions:setSchemaValidationMode](#setschemavalidationmode)
* [Custom Schema](#custom-schema)
    * [ServerOptions:setSchema](#setschema)
* [Operational Attributes](#operational-attributes)

Calling `LdapServer::useStorage()` automatically enables schema validation using the built-in RFC 4519
schema in `Strict` mode.

## Default Behavior

```php
use FreeDSx\Ldap\LdapServer;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\InMemoryStorage;

$server = new LdapServer();
$server->useStorage(new InMemoryStorage());
```

## What Gets Validated

Every `add` and `modify` is checked before reaching storage:

- At least one structural `objectClass` known to the schema is present.
- All `MUST` attributes for the object class chain are present.
- No attributes outside the `MUST` + `MAY` set appear (unless `extensibleObject` is included).
- Single-valued attributes carry at most one value.
- Attributes marked `NO-USER-MODIFICATION` are not writable by clients.

Failures return `objectClassViolation` (65), `undefinedAttributeType` (17), or `constraintViolation` (19)
with a diagnostic message naming the offending attribute or class.

## Entry Requirements

An entry needs a structural `objectClass` the schema recognises and every `MUST` attribute it requires.

```php
use FreeDSx\Ldap\Entry\Entry;

$entry = Entry::fromArray(
    'cn=alice,ou=people,dc=example,dc=com',
    [
        'objectClass' => 'inetOrgPerson',
        'cn'          => 'alice',
        'sn'          => 'Smith',   // MUST for inetOrgPerson
    ],
);
```

### extensibleObject

Adding `extensibleObject` as an auxiliary class bypasses the attribute-set checks.

```php
$entry = Entry::fromArray(
    'cn=alice,ou=people,dc=example,dc=com',
    [
        'objectClass' => ['inetOrgPerson', 'extensibleObject'],
        'cn'          => 'alice',
        'sn'          => 'Smith',
        'uidNumber'   => '1001',   // not in inetOrgPerson MAY; allowed via extensibleObject
    ],
);
```

## Validation Mode

------------------
#### setSchemaValidationMode

**Default**: `SchemaValidationMode::Strict`

| Mode | Behaviour |
|------|-----------|
| `Strict` | Violations are rejected with an LDAP error. |
| `Off` | All writes pass through without checks. |

```php
use FreeDSx\Ldap\LdapServer;
use FreeDSx\Ldap\Schema\SchemaValidationMode;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\InMemoryStorage;
use FreeDSx\Ldap\ServerOptions;

$server = new LdapServer(
    (new ServerOptions())->setSchemaValidationMode(SchemaValidationMode::Off)
);
$server->useStorage(new InMemoryStorage());
```

## Custom Schema

------------------
#### setSchema

Replaces the active schema. Use `StandardSchemaProvider::buildCore()->merge(...)` to extend the
standard definitions rather than replace them.

**Default**: `StandardSchemaProvider::buildCore()`

```php
use FreeDSx\Ldap\Schema\Definition\AttributeType;
use FreeDSx\Ldap\Schema\Definition\AttributeUsage;
use FreeDSx\Ldap\Schema\Definition\ObjectClass;
use FreeDSx\Ldap\Schema\Definition\ObjectClassType;
use FreeDSx\Ldap\Schema\Schema;
use FreeDSx\Ldap\Schema\StandardSchemaProvider;
use FreeDSx\Ldap\ServerOptions;

$schema = StandardSchemaProvider::buildCore()->merge(
    (new Schema())
        ->addAttributeType(new AttributeType(
            oid: '1.3.6.1.4.1.99999.1',
            names: ['myCustomAttr'],
            equalityOid: '2.5.13.2',
            usage: AttributeUsage::UserApplications,
        ))
        ->addObjectClass(new ObjectClass(
            oid: '1.3.6.1.4.1.99999.2',
            names: ['myCustomClass'],
            type: ObjectClassType::StructuralClass,
            superClassOids: ['2.5.6.6'],
            must: ['myCustomAttr'],
        ))
);

$options = (new ServerOptions())->setSchema($schema);

## Operational Attributes

`useStorage()` automatically populates and maintains server-managed operational attributes on every write. Clients
cannot modify these — they are flagged `NO-USER-MODIFICATION` in the schema and client attempts are rejected with
`constraintViolation`.

**Set on `add`:**

| Attribute | Value |
|---|---|
| `createTimestamp` | Current UTC time (`YYYYMMDDHHmmssZ`). |
| `modifyTimestamp` | Same as `createTimestamp` at add time. |
| `creatorsName` | DN of the bound user, or an empty string for anonymous. |
| `modifiersName` | Same as `creatorsName` at add time. |
| `entryUUID` | Random UUID v4 (RFC 4122). |
| `structuralObjectClass` | Most-specific structural objectClass. Only set when schema validation is enabled. |

**Updated on `modify` and `move`:** `modifyTimestamp` and `modifiersName` are refreshed. All other operational
attributes remain unchanged.

**`hasSubordinates` (dynamic):** Never stored. Injected into search results when requested via the `+` shorthand
or by name. Value is `TRUE` if the entry has at least one direct child, `FALSE` otherwise.
```
