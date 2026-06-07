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

namespace FreeDSx\Ldap\Server\SearchLimit;

use FreeDSx\Ldap\Server\AccessControl\Subject\SubjectMatcherInterface;
use FreeDSx\Ldap\Server\SearchLimits;

/**
 * Pairs a subject with the search limits applied to identities it matches.
 *
 * @api
 */
final readonly class SearchLimitRule
{
    public function __construct(
        public SubjectMatcherInterface $subject,
        public SearchLimits $limits,
    ) {}

    public static function for(
        SubjectMatcherInterface $subject,
        SearchLimits $limits,
    ): self {
        return new self(
            $subject,
            $limits,
        );
    }
}
