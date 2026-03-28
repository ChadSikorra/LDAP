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

namespace FreeDSx\Ldap\Server\Storage\Adapter;

use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entries;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Entry\Rdn;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Server\Storage\StorageAdapterInterface;

/**
 * An in-memory storage adapter backed by a plain PHP array.
 *
 * Suitable for single-process use cases: the Swoole server runner (all
 * connections share the same process memory), or pre-seeded read-only
 * use with the PCNTL runner (data seeded before run() is inherited by
 * all forked child processes).
 *
 * With the PCNTL runner, write operations performed by one child process
 * are not visible to other children or the parent.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class InMemoryStorageAdapter implements StorageAdapterInterface
{
    /**
     * Entries keyed by their normalised (lowercased) DN string.
     *
     * @var array<string, Entry>
     */
    private array $entries = [];

    /**
     * Pre-populate the adapter with a set of entries.
     */
    public function __construct(Entry ...$entries)
    {
        foreach ($entries as $entry) {
            $this->entries[$this->normalise($entry->getDn())] = $entry;
        }
    }

    public function get(Dn $dn): ?Entry
    {
        return $this->entries[$this->normalise($dn)] ?? null;
    }

    public function list(Dn $baseDn, int $scope): Entries
    {
        $normBase = $this->normalise($baseDn);
        $results = [];

        foreach ($this->entries as $normDn => $entry) {
            if ($this->isInScope($normDn, $normBase, $scope)) {
                $results[] = $entry;
            }
        }

        return new Entries(...$results);
    }

    public function verifyPassword(Dn $dn, string $password): bool
    {
        $entry = $this->get($dn);

        if ($entry === null) {
            return false;
        }

        $attr = $entry->get('userPassword');

        if ($attr === null) {
            return false;
        }

        foreach ($attr->getValues() as $stored) {
            if ($this->checkPassword($password, $stored)) {
                return true;
            }
        }

        return false;
    }

    public function add(Entry $entry): void
    {
        $this->entries[$this->normalise($entry->getDn())] = $entry;
    }

    public function delete(Dn $dn): void
    {
        unset($this->entries[$this->normalise($dn)]);
    }

    /**
     * @param Change[] $changes
     */
    public function update(Dn $dn, array $changes): void
    {
        $entry = $this->get($dn);

        if ($entry === null) {
            return;
        }

        foreach ($changes as $change) {
            $attribute = $change->getAttribute();
            $attrName = $attribute->getName();
            $values = $attribute->getValues();

            switch ($change->getType()) {
                case Change::TYPE_ADD:
                    $existing = $entry->get($attrName);
                    if ($existing !== null) {
                        $entry->get($attrName)?->add(...$values);
                    } else {
                        $entry->add($attribute);
                    }
                    break;

                case Change::TYPE_DELETE:
                    if (count($values) === 0) {
                        $entry->reset($attrName);
                    } else {
                        $entry->get($attrName)?->remove(...$values);
                    }
                    break;

                case Change::TYPE_REPLACE:
                    if (count($values) === 0) {
                        $entry->reset($attrName);
                    } else {
                        $entry->set($attribute);
                    }
                    break;
            }
        }
    }

    public function move(
        Dn $dn,
        Rdn $newRdn,
        bool $deleteOldRdn,
        ?Dn $newParent,
    ): void {
        $entry = $this->get($dn);

        if ($entry === null) {
            return;
        }

        $parent = $newParent ?? $dn->getParent();
        $newDnString = $parent !== null
            ? $newRdn->toString() . ',' . $parent->toString()
            : $newRdn->toString();

        $newDn = new Dn($newDnString);
        $newEntry = new Entry($newDn, ...$entry->getAttributes());

        if ($deleteOldRdn) {
            $oldRdn = $dn->getRdn();
            $newEntry->get($oldRdn->getName())?->remove($oldRdn->getValue());
        }

        // Add the new RDN attribute value
        $rdnName = $newRdn->getName();
        $rdnValue = $newRdn->getValue();
        $existing = $newEntry->get($rdnName);
        if ($existing !== null) {
            if (!$existing->has($rdnValue)) {
                $existing->add($rdnValue);
            }
        } else {
            $newEntry->set(new \FreeDSx\Ldap\Entry\Attribute($rdnName, $rdnValue));
        }

        $this->delete($dn);
        $this->add($newEntry);
    }

    private function normalise(Dn $dn): string
    {
        return strtolower($dn->toString());
    }

    private function isInScope(string $normDn, string $normBase, int $scope): bool
    {
        return match ($scope) {
            SearchRequest::SCOPE_BASE_OBJECT => $normDn === $normBase,
            SearchRequest::SCOPE_SINGLE_LEVEL => $this->isDirectChild($normDn, $normBase),
            SearchRequest::SCOPE_WHOLE_SUBTREE => $this->isAtOrBelow($normDn, $normBase),
            default => false,
        };
    }

    private function isAtOrBelow(string $normDn, string $normBase): bool
    {
        if ($normDn === $normBase) {
            return true;
        }

        return str_ends_with($normDn, ',' . $normBase);
    }

    private function isDirectChild(string $normDn, string $normBase): bool
    {
        if (!str_ends_with($normDn, ',' . $normBase)) {
            return false;
        }

        // Strip the base suffix and check there is exactly one RDN component left
        $prefix = substr($normDn, 0, strlen($normDn) - strlen(',' . $normBase));

        return !str_contains($prefix, ',');
    }

    /**
     * Verify a plain-text password against a (possibly hashed) stored value.
     *
     * Supports {SHA}, {SSHA}, {MD5}, {SMD5}, and plain-text storage.
     */
    private function checkPassword(string $plain, string $stored): bool
    {
        if (str_starts_with($stored, '{SHA}')) {
            return base64_encode(sha1($plain, true)) === substr($stored, 5);
        }

        if (str_starts_with($stored, '{SSHA}')) {
            $decoded = base64_decode(substr($stored, 6));
            $salt = substr($decoded, 20);

            return substr($decoded, 0, 20) === sha1($plain . $salt, true);
        }

        if (str_starts_with($stored, '{MD5}')) {
            return base64_encode(md5($plain, true)) === substr($stored, 5);
        }

        if (str_starts_with($stored, '{SMD5}')) {
            $decoded = base64_decode(substr($stored, 6));
            $salt = substr($decoded, 16);

            return substr($decoded, 0, 16) === md5($plain . $salt, true);
        }

        // Plain-text fallback
        return $plain === $stored;
    }
}
