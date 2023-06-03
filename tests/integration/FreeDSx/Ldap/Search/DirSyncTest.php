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

namespace integration\FreeDSx\Ldap\Search;

use FreeDSx\Ldap\LdapClient;
use FreeDSx\Ldap\Search\DirSync;
use FreeDSx\Ldap\Search\Filter\FilterInterface;
use FreeDSx\Ldap\Search\Filters;
use integration\FreeDSx\Ldap\LdapTestCase;

class DirSyncTest extends LdapTestCase
{
    private LdapClient $client;

    private DirSync $dirSync;

    private FilterInterface $filter;

    public function setUp(): void
    {
        if (!$this->isActiveDirectory()) {
            $this->markTestSkipped('Range retrieval is only testable against Active Directory.');
        }
        $this->client = $this->getClient();
        $this->bindClient($this->client);

        $this->filter = Filters::and(
            Filters::equal(
                'objectClass',
                'inetOrgPerson'
            ),
            Filters::not(Filters::equal(
                'isDeleted',
                'TRUE'
            ))
        );

        $this->dirSync = new DirSync(
            $this->client,
            null,
            $this->filter,
            'description'
        );
    }

    public function testPagingSync(): void
    {
        $all = $this->dirSync->getChanges();

        while ($this->dirSync->hasChanges()) {
            $all->add(...$this->dirSync->getChanges());
        }
        $this->assertCount(10001, $all);

        $entry = $this->client->readOrFail('cn=Vivie Niebudek,ou=Administrative,ou=FreeDSx-Test,dc=example,dc=com');
        $entry->set(
            'description',
            'foobar ' . rand()
        );
        $this->client->update($entry);

        $this->assertCount(
            1,
            $this->dirSync->getChanges()
        );
    }
}
