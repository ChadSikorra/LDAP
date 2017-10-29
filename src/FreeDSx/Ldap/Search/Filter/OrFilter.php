<?php
/**
 * This file is part of the FreeDSx package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Ldap\Search\Filter;

/**
 * Represents a logical 'or' filter. RFC 4511, 4.5.1
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class OrFilter implements FilterContainerInterface
{
    use FilterContainerTrait;

    protected const CHOICE_TAG = 1;
}
