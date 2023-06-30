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

namespace integration\FreeDSx\Ldap;

use FreeDSx\Ldap\ClientOptions;
use FreeDSx\Ldap\Entry\Entries;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\ConnectionException;
use FreeDSx\Ldap\LdapClient;
use FreeDSx\Ldap\Operation\Response\AddResponse;
use FreeDSx\Ldap\Operation\Response\BindResponse;
use FreeDSx\Ldap\Operation\Response\DeleteResponse;
use FreeDSx\Ldap\Operation\Response\ModifyDnResponse;
use FreeDSx\Ldap\Operation\Response\ModifyResponse;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Search\Filters;
use FreeDSx\Ldap\Search\Result\EntryResult;
use Throwable;

class LdapClientTest extends LdapTestCase
{
    private LdapClient $client;

    public function setUp(): void
    {
        $this->client = $this->getClient();
    }

    public function tearDown(): void
    {
        try {
            @$this->client->unbind();
        } catch (Throwable) {
        }
    }

    public function testUsernamePasswordBind(): void
    {
        $response = $this->client->bind(
            $_ENV['LDAP_USERNAME'],
            $_ENV['LDAP_PASSWORD']
        )->getResponse();

        $this->assertInstanceOf(
            BindResponse::class,
            $response
        );
        $this->assertSame(
            0,
            $response->getResultCode()
        );
    }

    public function testAnonymousBind(): void
    {
        $response = $this->client->send(Operations::bindAnonymously())
            ?->getResponse();

        $this->assertInstanceOf(
            BindResponse::class,
            $response
        );
        $this->assertSame(
            0,
            $response->getResultCode()
        );
    }

    public function testSaslBindWithAutoSelectingTheMechanism(): void
    {
        $response = $this->client->bindSasl($this->getSaslOptions());
        $response = $response->getResponse();

        $this->assertInstanceOf(
            BindResponse::class,
            $response
        );
        $this->assertSame(
            0,
            $response->getResultCode()
        );
    }

    public function testSaslBindWithCramMD5(): void
    {
        if ($this->isActiveDirectory()) {
            $this->markTestSkipped('CRAM-MD5 not supported on AD.');
        }
        $response = $this->client->bindSasl(
            $this->getSaslOptions(),
            'CRAM-MD5'
        );
        $response = $response->getResponse();

        $this->assertInstanceOf(
            BindResponse::class,
            $response
        );
        $this->assertSame(
            0,
            $response->getResultCode()
        );
    }

    public function testSaslBindWithDigestMD5(): void
    {
        $response = $this->client->bindSasl(
            $this->getSaslOptions(),
            'DIGEST-MD5'
        );
        $response = $response->getResponse();

        $this->assertInstanceOf(
            BindResponse::class,
            $response
        );
        $this->assertSame(
            0,
            $response->getResultCode()
        );
    }

    public function testSaslBindWithAnIntegritySecurityLayerIsFunctional(): void
    {
        $this->client->bindSasl(
            array_merge($this->getSaslOptions(), ['use_integrity' => true]),
            'DIGEST-MD5'
        );
        $entry = $this->client->read('', ['supportedSaslMechanisms']);

        $this->assertInstanceOf(
            Entry::class,
            $entry
        );
    }

    public function testCompareOperation(): void
    {
        $this->bindClient($this->client);

        $success = $this->client->compare(
            'cn=Birgit Pankhurst,ou=Janitorial,ou=FreeDSx-Test,dc=example,dc=com',
            'cn',
            'Birgit Pankhurst'
        );
        $failure = $this->client->compare(
            'cn=Birgit Pankhurst,ou=Janitorial,ou=FreeDSx-Test,dc=example,dc=com',
            'cn',
            'foo'
        );

        $this->assertTrue($success);
        $this->assertFalse($failure);
    }

    public function testCreateOperation(): void
    {
        $this->bindClient($this->client);

        $attributes = [
            'objectClass' => ['top', 'person', 'organizationalPerson', 'inetOrgPerson'],
            'cn' => ['Foo'],
            'sn' => ['Bar'],
            'description' => ['FreeDSx Unit Test'],
            'uid' => ['Foo'],
            'givenName' => ['Foo'],
        ];

        $response = $this->client->create(Entry::fromArray(
            'cn=Foo,ou=FreeDSx-Test,dc=example,dc=com',
            $attributes
        ))->getResponse();

        $this->assertInstanceOf(
            AddResponse::class,
            $response
        );
        $this->assertSame(
            0,
            $response->getResultCode()
        );

        # Testing across AD / OpenLDAP. Ignore the ObjectClass differences...
        unset($attributes['objectClass']);

        $entry = $this->client->readOrFail(
            'cn=Foo,ou=FreeDSx-Test,dc=example,dc=com',
            array_keys($attributes)
        );

        $this->assertSame(
            $attributes,
            $entry->toArray()
        );
    }

    public function testReadOperation(): void
    {
        $this->bindClient($this->client);

        $attributes = [
            'cn' => ['Carmelina Esposito'],
            'sn' => ['Esposito'],
            'description' => ["This is Carmelina Esposito's description"],
            'facsimileTelephoneNumber' => ['+1 415 116-9439'],
            'l' => ['San Jose'],
            'postalAddress' => ['Product Testing$San Jose'],
        ];
        $entry = $this->client->read(
            'cn=Carmelina Esposito,ou=Product Testing,ou=FreeDSx-Test,dc=example,dc=com',
            array_keys($attributes)
        );

        $this->assertInstanceOf(
            Entry::class,
            $entry
        );
        $this->assertSame(
            strtolower($entry->getDn()->toString()),
            strtolower('cn=Carmelina Esposito,ou=Product Testing,ou=FreeDSx-Test,dc=example,dc=com')
        );
        $this->assertSame(
            $entry->toArray(),
            $attributes
        );
    }

    public function testDeleteOperation(): void
    {
        $this->bindClient($this->client);

        $response = $this->client->delete('cn=Foo,ou=FreeDSx-Test,dc=example,dc=com')
            ->getResponse();

        $this->assertInstanceOf(
            DeleteResponse::class,
            $response
        );
        $this->assertSame(
            0,
            $response->getResultCode()
        );
    }

    public function testModifyOperation(): void
    {
        $this->bindClient($this->client);

        $entry = new Entry('cn=Kathrine Erbach,ou=Payroll,ou=FreeDSx-Test,dc=example,dc=com');
        $entry->reset('facsimileTelephoneNumber');
        $entry->remove('mobile', '+1 510 957-7341');
        $entry->add('mobile', '+1 555 555-5555');
        $entry->remove('homePhone', '+1 510 991-4348');
        $entry->set('title', 'Head Payroll Dude');

        $response = $this->client->update($entry)
            ->getResponse();

        $this->assertInstanceOf(ModifyResponse::class, $response);
        $this->assertSame(0, $response->getResultCode());
        $this->assertEmpty($entry->changes()->toArray());

        $modified = $this->client->readOrFail(
            'cn=Kathrine Erbach,ou=Payroll,ou=FreeDSx-Test,dc=example,dc=com',
            [
                'facsimileTelephoneNumber',
                'mobile',
                'homePhone',
                'title',
            ]
        );
        $this->assertSame(
            [
                'mobile' => ['+1 555 555-5555'],
                'title' => ['Head Payroll Dude']
            ],
            $modified->toArray()
        );
    }

    public function testRenameOperation(): void
    {
        $this->bindClient($this->client);

        $result = $this->client->rename(
            'cn=Arleen Sevigny,ou=Janitorial,ou=FreeDSx-Test,dc=example,dc=com',
            'cn=Arleen Sevigny-Foo'
        );
        $entry = $this->client->readOrFail(
            'cn=Arleen Sevigny-Foo,ou=Janitorial,ou=FreeDSx-Test,dc=example,dc=com',
            ['cn']
        );

        $this->assertInstanceOf(
            ModifyDnResponse::class,
            $result->getResponse()
        );
        $this->assertInstanceOf(
            Entry::class,
            $entry
        );
        $this->assertSame(
            ['Arleen Sevigny-Foo'],
            $entry->get('cn')?->getValues()
        );
    }

    public function testRenameWithoutDeleteOperation(): void
    {
        if ($this->isActiveDirectory()) {
            $this->markTestSkipped('Rename without delete not supported in Active Directory.');
        }
        $this->bindClient($this->client);

        $result = $this->client->rename(
            'cn=Farouk Langdon,ou=Administrative,ou=FreeDSx-Test,dc=example,dc=com',
            'cn=Farouk Langdon-Bar',
            false
        );
        $entry = $this->client->read(
            'cn=Farouk Langdon-Bar,ou=Administrative,ou=FreeDSx-Test,dc=example,dc=com',
            ['cn']
        );

        $this->assertInstanceOf(
            ModifyDnResponse::class,
            $result->getResponse()
        );
        $this->assertInstanceOf(
            Entry::class,
            $entry
        );
        $this->assertContains(
            'Farouk Langdon',
            (array) $entry->get('cn')?->getValues()
        );
        $this->assertContains(
            'Farouk Langdon-Bar',
            (array) $entry->get('cn')?->getValues()
        );
    }

    public function testMoveOperation(): void
    {
        $this->markTestSkipped('Rename without delete not supported in Active Directory.');

        /*
        $this->bindClient($this->client);

        $result = $this->client->move('cn=Minne Schmelzel,ou=Janitorial,ou=FreeDSx-Test,dc=example,dc=com', 'ou=Administrative,ou=FreeDSx-Test,dc=example,dc=com');
        $entry = $this->client->read('cn=Minne Schmelzel,ou=Administrative,ou=FreeDSx-Test,dc=example,dc=com');

        $this->assertInstanceOf(ModifyDnResponse::class, $result->getResponse());
        $this->assertInstanceOf(Entry::class, $entry);
        */
    }

    public function testSearchOperationWithEntryHandler(): void
    {
        $this->bindClient($this->client);

        $entries = new Entries();
        $op = Operations::search(Filters::raw('(&(objectClass=inetOrgPerson)(cn=A*))'))
            ->useEntryHandler(fn (EntryResult $result) => $entries->add($result->getEntry()));

        $this->client->search($op);

        $this->assertSame(
            843,
            $entries->count()
        );
    }

    public function testSubSearchOperation(): void
    {
        $this->bindClient($this->client);

        $entries = $this->client->search(Operations::search(
            Filters::raw('(&(objectClass=inetOrgPerson)(cn=A*))')
        ));

        $this->assertInstanceOf(
            Entries::class,
            $entries
        );
        $this->assertSame(
            843,
            $entries->count()
        );
    }

    public function testListSearchOperation(): void
    {
        $this->bindClient($this->client);

        $entries = $this->client->search(Operations::list(
            Filters::raw('(&(objectClass=inetOrgPerson)(cn=A*))'),
            'ou=Payroll,ou=FreeDSx-Test,dc=example,dc=com'
        ));

        $this->assertInstanceOf(
            Entries::class,
            $entries
        );
        $this->assertSame(
            100,
            $entries->count()
        );

        foreach ($entries->toArray() as $entry) {
            $this->assertSame(
                strtolower('ou=Payroll,ou=FreeDSx-Test,dc=example,dc=com'),
                strtolower((string) $entry->getDn()->getParent()?->toString())
            );
        }
    }

    public function testWhoAmI(): void
    {
        $this->bindClient($this->client);

        $this->assertMatchesRegularExpression(
            '/^(dn|u):.*/',
            (string) $this->client->whoami()
        );
    }

    public function testSetOptionsDisconnectsIfRequested(): void
    {
        $this->bindClient($this->client);

        $this->client->setOptions(
            options: new ClientOptions(),
            forceDisconnect: true,
        );

        $this->assertFalse($this->client->isConnected());
    }

    public function testStartTls(): void
    {
        $this->client = $this->getClient();
        $this->client->startTls();

        $this->assertTrue($this->client->isConnected());
    }

    public function testStartTlsFailure(): void
    {
        $this->client = $this->getClient(
            $this->makeOptions()
                ->setServers(['foo.com'])
        );

        $this->expectException(ConnectionException::class);
        @$this->client->startTls();
    }

    public function testStartTlsIgnoreCertValidation(): void
    {
        $this->client = $this->getClient(
            $this->makeOptions()
                ->setServers(['foo.com'])
                ->setSslValidateCert(false)
        );

        $this->client->startTls();
        $this->assertTrue($this->client->isConnected());
    }

    public function testUseSsl(): void
    {
        $this->client = $this->getClient(
            $this->makeOptions()
                ->setUseSsl(true)
                ->setPort(636)
        );
        $this->client->read('');

        $this->assertTrue($this->client->isConnected());
    }

    public function testItCanWorkOverUnixSocket(): void
    {
        if ($this->isActiveDirectory()) {
            $this->markTestSkipped('Connecting via a unix socket only tested on OpenLDAP.');
        }
        $this->client = $this->getClient(
            $this->makeOptions()
                ->setTransport('unix')
                ->setServers(['/var/run/slapd/ldapi'])
        );
        $entry = $this->client->read('');

        $this->assertNotNull($entry);
    }

    public function testUseSslFailure(): void
    {
        $this->client = $this->getClient(
            $this->makeOptions()
                ->setServers(['foo.com'])
                ->setUseSsl(true)
                ->setPort(636)
        );

        $this->expectException(ConnectionException::class);

        $this->client->read('');
    }

    public function testUseSslIgnoreCertValidation(): void
    {
        $this->client = $this->getClient(
            $this->makeOptions()
                ->setServers(['foo.com'])
                ->setSslValidateCert(false)
                ->setUseSsl(true)
                ->setPort(636)
        );

        $this->client->read('');

        $this->assertTrue($this->client->isConnected());
    }

    protected function getSaslOptions(): array
    {
        if ($this->isActiveDirectory()) {
            return [
                'username' => 'admin',
                'password' => $_ENV['LDAP_PASSWORD'],
                'host' => 'ADDC3.example.com'
            ];
        } else {
            return [
                'username' => 'WillifoA',
                'password' => 'Password1',
            ];
        }
    }
}
