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

/**
 * Ordered per-identity search-limit rules.
 *
 * Identities matching none fall back to the global limits.
 *
 * @api
 */
final readonly class SearchLimitRules
{
    /**
     * @param SearchLimitRule[] $rules Evaluated in order; first match wins.
     */
    public function __construct(
        public array $rules = [],
    ) {}

    public function withRules(SearchLimitRule ...$rules): self
    {
        return new self($rules);
    }

    public function isEmpty(): bool
    {
        return $this->rules === [];
    }
}
