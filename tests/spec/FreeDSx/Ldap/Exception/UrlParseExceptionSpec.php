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

namespace spec\FreeDSx\Ldap\Exception;

use FreeDSx\Ldap\Exception\UrlParseException;
use PhpSpec\ObjectBehavior;

class UrlParseExceptionSpec extends ObjectBehavior
{
    public function it_is_initializable(): void
    {
        $this->shouldHaveType(UrlParseException::class);
    }

    public function it_should_extend_exception(): void
    {
        $this->shouldBeAnInstanceOf('\Exception');
    }
}
