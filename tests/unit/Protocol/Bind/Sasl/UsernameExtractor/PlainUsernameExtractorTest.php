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

namespace Tests\Unit\FreeDSx\Ldap\Protocol\Bind\Sasl\UsernameExtractor;

use FreeDSx\Ldap\Protocol\Bind\Sasl\UsernameExtractor\PlainUsernameExtractor;
use FreeDSx\Sasl\Mechanism\MechanismName;
use PHPUnit\Framework\TestCase;

final class PlainUsernameExtractorTest extends TestCase
{
    private PlainUsernameExtractor $subject;

    protected function setUp(): void
    {
        $this->subject = new PlainUsernameExtractor();
    }

    public function test_it_extracts_the_authcid_as_the_username(): void
    {
        // PLAIN format: "authzid\x00authcid\x00passwd"
        $credentials = "authzid\x00cn=user,dc=foo,dc=bar\x0012345";

        self::assertSame(
            'cn=user,dc=foo,dc=bar',
            $this->subject->extractUsername(MechanismName::PLAIN, $credentials),
        );
    }
}
