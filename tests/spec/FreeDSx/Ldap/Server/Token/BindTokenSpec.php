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

namespace spec\FreeDSx\Ldap\Server\Token;

use FreeDSx\Ldap\Server\Token\BindToken;
use FreeDSx\Ldap\Server\Token\TokenInterface;
use PhpSpec\ObjectBehavior;

class BindTokenSpec extends ObjectBehavior
{
    public function let(): void
    {
        $this->beConstructedWith('foo', 'bar');
    }

    public function it_is_initializable(): void
    {
        $this->shouldHaveType(BindToken::class);
    }

    public function it_should_implement_token_interface(): void
    {
        $this->shouldImplement(TokenInterface::class);
    }

    public function it_should_get_the_username(): void
    {
        $this->getUsername()->shouldBeEqualTo('foo');
    }

    public function it_should_get_the_password(): void
    {
        $this->getPassword()->shouldBeEqualTo('bar');
    }

    public function it_should_get_the_version(): void
    {
        $this->getVersion()->shouldBeEqualTo(3);
    }
}
