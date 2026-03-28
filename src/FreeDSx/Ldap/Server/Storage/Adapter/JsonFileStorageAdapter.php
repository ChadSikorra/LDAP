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

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entries;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Entry\Rdn;
use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Server\Storage\StorageAdapterInterface;

/**
 * A file-backed storage adapter that persists the directory as a JSON file.
 *
 * Safe for use with the PCNTL server runner: write operations are serialised
 * using flock(LOCK_EX), so concurrent child processes do not corrupt the file.
 * An in-memory cache is invalidated via filemtime checks to avoid re-reading
 * the file on every read operation within a single forked process.
 *
 * Note: when used with the Swoole server runner, standard flock/fread calls
 * are blocking and will stall the event loop. Use the InMemoryStorageAdapter
 * with Swoole, or a Swoole-coroutine-aware file I/O layer instead.
 *
 * JSON format:
 * {
 *   "cn=admin,dc=example,dc=com": {
 *     "dn": "cn=admin,dc=example,dc=com",
 *     "attributes": {
 *       "cn": ["admin"],
 *       "userPassword": ["{SHA}..."]
 *     }
 *   }
 * }
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class JsonFileStorageAdapter implements StorageAdapterInterface
{
    /**
     * @var array<string, Entry>|null
     */
    private ?array $cache = null;

    private int $cacheMtime = 0;

    public function __construct(private readonly string $filePath)
    {
    }

    public function get(Dn $dn): ?Entry
    {
        return $this->read()[$this->normalise($dn)] ?? null;
    }

    public function list(Dn $baseDn, int $scope): Entries
    {
        $normBase = $this->normalise($baseDn);
        $results = [];

        foreach ($this->read() as $normDn => $entry) {
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
        $this->withLock(function (array $data) use ($entry): array {
            $data[$this->normalise($entry->getDn())] = $this->entryToArray($entry);

            return $data;
        });
    }

    public function delete(Dn $dn): void
    {
        $normDn = $this->normalise($dn);
        $this->withLock(function (array $data) use ($normDn): array {
            unset($data[$normDn]);

            return $data;
        });
    }

    /**
     * @param Change[] $changes
     */
    public function update(Dn $dn, array $changes): void
    {
        $normDn = $this->normalise($dn);
        $this->withLock(function (array $data) use ($normDn, $changes): array {
            if (!isset($data[$normDn])) {
                return $data;
            }

            $entry = $this->arrayToEntry($data[$normDn]);

            foreach ($changes as $change) {
                $attribute = $change->getAttribute();
                $attrName = $attribute->getName();
                $values = $attribute->getValues();

                switch ($change->getType()) {
                    case Change::TYPE_ADD:
                        $existing = $entry->get($attrName);
                        if ($existing !== null) {
                            $existing->add(...$values);
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

            $data[$normDn] = $this->entryToArray($entry);

            return $data;
        });
    }

    public function move(
        Dn $dn,
        Rdn $newRdn,
        bool $deleteOldRdn,
        ?Dn $newParent,
    ): void {
        $normOld = $this->normalise($dn);
        $this->withLock(function (array $data) use ($normOld, $dn, $newRdn, $deleteOldRdn, $newParent): array {
            if (!isset($data[$normOld])) {
                return $data;
            }

            $entry = $this->arrayToEntry($data[$normOld]);

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

            $rdnName = $newRdn->getName();
            $rdnValue = $newRdn->getValue();
            $existing = $newEntry->get($rdnName);
            if ($existing !== null) {
                if (!$existing->has($rdnValue)) {
                    $existing->add($rdnValue);
                }
            } else {
                $newEntry->set(new Attribute($rdnName, $rdnValue));
            }

            unset($data[$normOld]);
            $data[$this->normalise($newDn)] = $this->entryToArray($newEntry);

            return $data;
        });
    }

    /**
     * @return array<string, Entry>
     */
    private function read(): array
    {
        if (!file_exists($this->filePath)) {
            $this->cache = [];
            $this->cacheMtime = 0;

            return $this->cache;
        }

        $mtime = (int) filemtime($this->filePath);

        if ($this->cache !== null && $this->cacheMtime === $mtime) {
            return $this->cache;
        }

        $contents = file_get_contents($this->filePath);

        if ($contents === false || $contents === '') {
            $this->cache = [];
            $this->cacheMtime = $mtime;

            return $this->cache;
        }

        $raw = json_decode($contents, true);

        if (!is_array($raw)) {
            $this->cache = [];
            $this->cacheMtime = $mtime;

            return $this->cache;
        }

        $entries = [];
        foreach ($raw as $normDn => $data) {
            if (!is_string($normDn)) {
                continue;
            }
            $entries[$normDn] = $this->arrayToEntry($data);
        }

        $this->cache = $entries;
        $this->cacheMtime = $mtime;

        return $this->cache;
    }

    /**
     * Open the file with an exclusive lock, call $mutation with the current
     * data array, write back the result, then release the lock.
     *
     * @param callable(array<string, mixed>): array<string, mixed> $mutation
     */
    private function withLock(callable $mutation): void
    {
        $handle = fopen($this->filePath, 'c+');

        if ($handle === false) {
            throw new RuntimeException(sprintf(
                'Unable to open storage file: %s',
                $this->filePath
            ));
        }

        if (!flock($handle, LOCK_EX)) {
            fclose($handle);
            throw new RuntimeException(sprintf(
                'Unable to acquire exclusive lock on storage file: %s',
                $this->filePath
            ));
        }

        try {
            $size = fstat($handle)['size'] ?? 0;
            $contents = $size > 0 ? fread($handle, $size) : '';
            $rawDecoded = ($contents !== '' && $contents !== false)
                ? json_decode($contents, true)
                : null;
            $data = [];
            if (is_array($rawDecoded)) {
                foreach ($rawDecoded as $key => $value) {
                    if (is_string($key)) {
                        $data[$key] = $value;
                    }
                }
            }

            $data = $mutation($data);

            ftruncate($handle, 0);
            rewind($handle);
            fwrite($handle, json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE) ?: '{}');
        } finally {
            flock($handle, LOCK_UN);
            fclose($handle);
            $this->cache = null;
        }
    }

    /**
     * @return array{dn: string, attributes: array<string, list<string>>}
     */
    private function entryToArray(Entry $entry): array
    {
        $attributes = [];
        foreach ($entry->getAttributes() as $attribute) {
            $attributes[$attribute->getName()] = array_values($attribute->getValues());
        }

        return [
            'dn' => $entry->getDn()->toString(),
            'attributes' => $attributes,
        ];
    }

    private function arrayToEntry(mixed $data): Entry
    {
        if (!is_array($data)) {
            return new Entry(new Dn(''));
        }

        $dn = isset($data['dn']) && is_string($data['dn']) ? $data['dn'] : '';

        $attributes = [];
        if (isset($data['attributes']) && is_array($data['attributes'])) {
            foreach ($data['attributes'] as $name => $values) {
                if (!is_string($name) || !is_array($values)) {
                    continue;
                }
                $stringValues = [];
                foreach ($values as $v) {
                    if (is_string($v)) {
                        $stringValues[] = $v;
                    }
                }
                $attributes[] = new Attribute($name, ...$stringValues);
            }
        }

        return new Entry(new Dn($dn), ...$attributes);
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

        return $plain === $stored;
    }
}
