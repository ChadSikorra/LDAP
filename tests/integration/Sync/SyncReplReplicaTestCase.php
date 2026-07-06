<?php

declare(strict_types=1);

/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tests\Integration\FreeDSx\Ldap\Sync;

use FreeDSx\Ldap\ClientOptions;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\ReferralException;
use FreeDSx\Ldap\LdapClient;
use Tests\Integration\FreeDSx\Ldap\ServerTestCase;
use Throwable;

/**
 * A read-only replica mirroring a locally spawned provider over RFC 4533.
 */
abstract class SyncReplReplicaTestCase extends ServerTestCase
{
    public function setUp(): void
    {
        $this->setServerMode('ldap-replica');

        parent::setUp();
    }

    public function test_seeded_entries_replicate_to_the_replica(): void
    {
        self::assertNotNull($this->waitForReplica('cn=alice,ou=people,dc=foo,dc=bar'));
    }

    public function test_an_add_on_the_provider_propagates_to_the_replica(): void
    {
        $this->writeToProvider(static function (LdapClient $provider): void {
            $provider->create(Entry::fromArray(
                'cn=dave,ou=people,dc=foo,dc=bar',
                [
                    'objectClass' => 'inetOrgPerson',
                    'cn' => 'dave',
                    'sn' => 'Davis',
                ],
            ));
        });

        self::assertNotNull($this->waitForReplica('cn=dave,ou=people,dc=foo,dc=bar'));
    }

    public function test_a_delete_on_the_provider_propagates_to_the_replica(): void
    {
        $this->writeToProvider(static function (LdapClient $provider): void {
            $provider->create(Entry::fromArray(
                'cn=eve,ou=people,dc=foo,dc=bar',
                [
                    'objectClass' => 'inetOrgPerson',
                    'cn' => 'eve',
                    'sn' => 'Evans',
                ],
            ));
        });
        self::assertNotNull($this->waitForReplica('cn=eve,ou=people,dc=foo,dc=bar'));

        $this->writeToProvider(static function (LdapClient $provider): void {
            $provider->delete('cn=eve,ou=people,dc=foo,dc=bar');
        });
        self::assertNull($this->waitForReplicaGone('cn=eve,ou=people,dc=foo,dc=bar'));
    }

    public function test_a_client_write_to_the_replica_is_referred_to_the_provider(): void
    {
        self::assertNotNull($this->waitForReplica('cn=alice,ou=people,dc=foo,dc=bar'));

        $client = $this->buildClient('tcp');
        $client->bind(
            'cn=user,dc=foo,dc=bar',
            '12345',
        );

        try {
            $this->expectException(ReferralException::class);
            $client->create(Entry::fromArray(
                'cn=nope,ou=people,dc=foo,dc=bar',
                [
                    'objectClass' => 'inetOrgPerson',
                    'cn' => 'nope',
                    'sn' => 'Nope',
                ],
            ));
        } finally {
            $client->unbind();
        }
    }

    private function waitForReplica(
        string $dn,
        float $timeoutSeconds = 15.0,
    ): ?Entry {
        $deadline = microtime(true) + $timeoutSeconds;

        do {
            $entry = $this->tryReadFromReplica($dn);

            if ($entry !== null) {
                return $entry;
            }

            usleep(100_000);
        } while (microtime(true) < $deadline);

        return null;
    }

    private function waitForReplicaGone(
        string $dn,
        float $timeoutSeconds = 15.0,
    ): ?Entry {
        $deadline = microtime(true) + $timeoutSeconds;

        do {
            $entry = $this->tryReadFromReplica($dn);

            if ($entry === null) {
                return null;
            }

            usleep(100_000);
        } while (microtime(true) < $deadline);

        return $entry;
    }

    private function tryReadFromReplica(string $dn): ?Entry
    {
        try {
            $client = $this->buildClient('tcp');
            $client->bind(
                'cn=user,dc=foo,dc=bar',
                '12345',
            );
            $entry = $client->read($dn);
            $client->unbind();

            return $entry;
        } catch (Throwable) {
            return null;
        }
    }

    /**
     * @param callable(LdapClient): void $write
     */
    private function writeToProvider(callable $write): void
    {
        $provider = $this->getClient(
            (new ClientOptions())
                ->setPort(10391)
                ->setServers(['127.0.0.1'])
                ->setSslValidateCert(false),
        );

        try {
            $provider->bind(
                'cn=user,dc=foo,dc=bar',
                '12345',
            );
            $write($provider);
        } finally {
            $provider->unbind();
        }
    }
}
