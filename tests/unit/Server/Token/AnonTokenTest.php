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

namespace Tests\Unit\FreeDSx\Ldap\Server\Token;

use FreeDSx\Ldap\Server\Token\AnonToken;
use PHPUnit\Framework\TestCase;

final class AnonTokenTest extends TestCase
{
    private AnonToken $subject;

    protected function setUp(): void
    {
        $this->subject = new AnonToken('foo');
    }

    public function test_it_should_get_the_username(): void
    {
        self::assertSame(
            'foo',
            $this->subject->getUsername(),
        );
    }

    public function test_it_should_get_a_null_password(): void
    {
        self::assertNull($this->subject->getPassword());
        ;
    }

    public function test_it_should_get_the_version(): void
    {
        self::assertSame(
            3,
            $this->subject->getVersion(),
        );
    }

    public function test_it_should_return_a_uuid_as_its_id(): void
    {
        self::assertMatchesRegularExpression(
            '/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/',
            $this->subject->getId(),
        );
    }

    public function test_it_should_return_a_unique_id_per_instance(): void
    {
        $other = new AnonToken('foo');

        self::assertNotSame(
            $this->subject->getId(),
            $other->getId(),
        );
    }
}
