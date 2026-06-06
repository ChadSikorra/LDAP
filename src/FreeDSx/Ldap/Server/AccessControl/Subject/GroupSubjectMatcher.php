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

namespace FreeDSx\Ldap\Server\AccessControl\Subject;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Server\AccessControl\BackendAwareInterface;
use FreeDSx\Ldap\Server\Backend\LdapBackendInterface;
use FreeDSx\Ldap\Server\Token\AuthenticatedTokenInterface;
use FreeDSx\Ldap\Server\Token\TokenInterface;
use LogicException;

/**
 * Matches when the bound DN is a member of the given LDAP group entry.
 *
 * The group entry is fetched from the backend once per token ID and cached.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class GroupSubjectMatcher implements SubjectMatcherInterface, BackendAwareInterface
{
    private readonly Dn $groupDn;

    private readonly int $maxCacheSize;

    private ?LdapBackendInterface $backend = null;

    /**
     * @var array<string, ?Entry>
     */
    private array $cache = [];

    public function __construct(
        string $groupDn,
        private readonly string $memberAttribute = 'member',
        int $maxCacheSize = 200,
    ) {
        $this->groupDn = new Dn($groupDn);
        $this->maxCacheSize = $maxCacheSize;
    }

    public function setBackend(LdapBackendInterface $backend): void
    {
        $this->backend = $backend;
    }

    public function matches(
        TokenInterface $token,
        Dn $targetDn,
    ): bool {
        if ($this->backend === null) {
            return false;
        }

        if (!$token instanceof AuthenticatedTokenInterface) {
            return false;
        }

        $entry = $this->getGroupEntry($token);
        if ($entry === null) {
            return false;
        }

        $memberAttr = $entry->get($this->memberAttribute);
        if ($memberAttr === null) {
            return false;
        }

        $resolvedDn = $token->getResolvedDn()->normalize()->toString();

        foreach ($memberAttr->getValues() as $value) {
            if ((new Dn($value))->normalize()->toString() === $resolvedDn) {
                return true;
            }
        }

        return false;
    }

    private function getGroupEntry(TokenInterface $token): ?Entry
    {
        if ($this->maxCacheSize === 0) {
            return $this->backend()->get($this->groupDn);
        }

        $id = $token->getId();
        if (!array_key_exists($id, $this->cache)) {
            $this->evictOldestIfFull();
            $this->cache[$id] = $this->backend()->get($this->groupDn);
        }

        return $this->cache[$id];
    }

    private function backend(): LdapBackendInterface
    {
        if ($this->backend === null) {
            throw new LogicException('No backend set on GroupSubjectMatcher; call setBackend() before use.');
        }

        return $this->backend;
    }

    private function evictOldestIfFull(): void
    {
        if (count($this->cache) < $this->maxCacheSize) {
            return;
        }

        $oldest = array_key_first($this->cache);

        if ($oldest === null) {
            return;
        }

        unset($this->cache[$oldest]);
    }
}
