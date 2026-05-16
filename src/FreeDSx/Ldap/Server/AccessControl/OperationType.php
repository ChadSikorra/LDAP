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

namespace FreeDSx\Ldap\Server\AccessControl;

use FreeDSx\Ldap\Operation\Request\AddRequest;
use FreeDSx\Ldap\Operation\Request\CompareRequest;
use FreeDSx\Ldap\Operation\Request\DeleteRequest;
use FreeDSx\Ldap\Operation\Request\ModifyDnRequest;
use FreeDSx\Ldap\Operation\Request\ModifyRequest;
use FreeDSx\Ldap\Operation\Request\RequestInterface;
use FreeDSx\Ldap\Operation\Request\SearchRequest;

enum OperationType: string
{
    case Search = 'search';
    case Add = 'add';
    case Modify = 'modify';
    case Delete = 'delete';
    case ModifyDn = 'modify_dn';
    case Compare = 'compare';
    case PasswordModify = 'password_modify';

    public static function fromRequest(RequestInterface $request): ?self
    {
        return match (true) {
            $request instanceof AddRequest => self::Add,
            $request instanceof ModifyRequest => self::Modify,
            $request instanceof DeleteRequest => self::Delete,
            $request instanceof ModifyDnRequest => self::ModifyDn,
            $request instanceof CompareRequest => self::Compare,
            $request instanceof SearchRequest => self::Search,
            default => null,
        };
    }
}
