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

namespace Tests\Unit\FreeDSx\Ldap\Server\AccessControl;

use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Operation\Request\AddRequest;
use FreeDSx\Ldap\Operation\Request\CompareRequest;
use FreeDSx\Ldap\Operation\Request\DeleteRequest;
use FreeDSx\Ldap\Operation\Request\ModifyDnRequest;
use FreeDSx\Ldap\Operation\Request\ModifyRequest;
use FreeDSx\Ldap\Operation\Request\RequestInterface;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Search\Filters;
use FreeDSx\Ldap\Server\AccessControl\OperationTargetDn;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class OperationTargetDnTest extends TestCase
{
    #[DataProvider('provideRequests')]
    public function test_it_resolves_the_target_dn(
        RequestInterface $request,
        ?string $expected,
    ): void {
        self::assertSame(
            $expected,
            OperationTargetDn::of($request)?->toString(),
        );
    }

    /**
     * @return array<string, array{RequestInterface, ?string}>
     */
    public static function provideRequests(): array
    {
        return [
            'add uses the entry dn' => [
                new AddRequest(Entry::create('cn=add,dc=foo,dc=bar')),
                'cn=add,dc=foo,dc=bar',
            ],
            'modify uses the request dn' => [
                new ModifyRequest('cn=mod,dc=foo,dc=bar', Change::replace('cn', 'x')),
                'cn=mod,dc=foo,dc=bar',
            ],
            'delete uses the request dn' => [
                new DeleteRequest('cn=del,dc=foo,dc=bar'),
                'cn=del,dc=foo,dc=bar',
            ],
            'modify dn uses the source dn' => [
                new ModifyDnRequest('cn=ren,dc=foo,dc=bar', 'cn=new', true),
                'cn=ren,dc=foo,dc=bar',
            ],
            'compare uses the request dn' => [
                new CompareRequest('cn=cmp,dc=foo,dc=bar', Filters::equal('cn', 'x')),
                'cn=cmp,dc=foo,dc=bar',
            ],
            'search has no single target' => [
                (new SearchRequest(Filters::present('cn')))->base('dc=foo,dc=bar'),
                null,
            ],
        ];
    }
}
