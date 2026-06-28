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

namespace FreeDSx\Ldap\Sync\Provider;

use FreeDSx\Ldap\Exception\InvalidArgumentException;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\ReplicaId;
use FreeDSx\Ldap\Sync\Provider\Exception\MalformedSyncCookieException;
use JsonException;

/**
 * Opaque, versioned RFC 4533 sync cookie carrying the origin replica and its seq high-water mark.
 *
 * @api
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class SyncCookie
{
    /**
     * Encoding version; bumped if the blob grows (e.g. a per-origin vector for multi-master).
     */
    private const VERSION = 1;

    public function __construct(
        public ReplicaId $origin,
        public int $seq,
    ) {
        if ($this->seq < 0) {
            throw new InvalidArgumentException('A sync cookie seq cannot be negative.');
        }
    }

    public function encode(): string
    {
        return base64_encode(json_encode(
            [
                'v' => self::VERSION,
                'origin' => (string) $this->origin,
                'seq' => $this->seq,
            ],
            JSON_THROW_ON_ERROR,
        ));
    }

    /**
     * @throws MalformedSyncCookieException
     */
    public static function decode(string $cookie): self
    {
        $json = base64_decode($cookie, true);

        if ($json === false) {
            throw new MalformedSyncCookieException('The sync cookie is not valid base64.');
        }

        try {
            $data = json_decode(
                $json,
                true,
                flags: JSON_THROW_ON_ERROR,
            );
        } catch (JsonException $e) {
            throw new MalformedSyncCookieException(
                'The sync cookie is not valid JSON.',
                previous: $e,
            );
        }

        if (!is_array($data) || ($data['v'] ?? null) !== self::VERSION) {
            throw new MalformedSyncCookieException('The sync cookie has an unsupported version.');
        }

        $origin = $data['origin'] ?? null;
        $seq = $data['seq'] ?? null;

        if (!is_string($origin) || $origin === '' || !is_int($seq) || $seq < 0) {
            throw new MalformedSyncCookieException('The sync cookie is missing a valid origin or seq.');
        }

        return new self(
            new ReplicaId($origin),
            $seq,
        );
    }
}
