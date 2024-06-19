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

namespace integration\FreeDSx\Ldap\Sync;

use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\CancelRequestException;
use FreeDSx\Ldap\Sync\Result\SyncEntryResult;
use integration\FreeDSx\Ldap\LdapTestCase;

class SyncReplTest extends LdapTestCase
{
    public function testItCanPerformPollingSync(): void
    {
        $entries = [];

        $client = $this->getClient();
        $this->bindClient($client);

        $client
            ->syncRepl()
            ->poll(fn (SyncEntryResult $result) => array_push($entries, $result));

        $this->assertGreaterThan(
            0,
            $entries,
        );
    }

    public function testItCanPerformPollingSyncForContentUpdates(): void
    {
        $entries = [];

        $client = $this->getClient();
        $this->bindClient($client);

        $saved_cookie = null;
        $syncRepl = $client->syncRepl();
        $syncRepl->useCookieHandler(function(string $cookie) use (&$saved_cookie) {
            $saved_cookie = $cookie;
        });
        $syncRepl->poll();

        $entry = new Entry('cn=Kathrine Erbach,ou=Payroll,ou=FreeDSx-Test,dc=example,dc=com');
        $entry->add('mobile', '+1 444 444-4444');
        $entry->set('title', 'Random Employee');
        $client->update($entry);

        $syncRepl = $client->syncRepl();
        $syncRepl->useCookie($saved_cookie);
        $syncRepl->poll(fn (SyncEntryResult $result) => array_push($entries, $result));

        $this->assertCount(1, $entries);
    }

    public function testItCanCancelTheSync(): void
    {
        $client = $this->getClient();
        $this->bindClient($client);

        $count = 0;
        $client
            ->syncRepl()
            ->listen(function () use (&$count): void {
                if ($count === 10) {
                    throw new CancelRequestException();
                }
                $count++;
            });

        $this->assertSame(
            10,
            $count,
            'It stopped on the 10th result.'
        );
    }
}
