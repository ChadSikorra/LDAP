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

namespace FreeDSx\Ldap\Server\PasswordPolicy;

use DateTimeImmutable;
use FreeDSx\Ldap\Exception\InvalidArgumentException;
use FreeDSx\Ldap\Exception\PasswordPolicyException;
use FreeDSx\Ldap\Schema\Definition\GeneralizedTime;
use FreeDSx\Ldap\Schema\Definition\SyntaxOid;

/**
 * One pwdHistory value (draft-behera-10 §5.3.7): time#syntaxOID#length#data.
 */
final readonly class HistoryEntry
{
    public function __construct(
        public DateTimeImmutable $changedAt,
        public string $syntaxOid,
        public string $data,
    ) {}

    /**
     * Decode a pwdHistory attribute value.
     *
     * @throws PasswordPolicyException when the value does not conform to the spec.
     */
    public static function decode(string $value): self
    {
        $timeEnd = self::expectDelimiter(
            $value,
            0,
            'time',
        );
        $syntaxEnd = self::expectDelimiter(
            $value,
            $timeEnd + 1,
            'syntax',
        );
        $lengthEnd = self::expectDelimiter(
            $value,
            $syntaxEnd + 1,
            'length',
        );

        $timeRaw = substr(
            $value,
            0,
            $timeEnd,
        );
        $syntaxOid = substr(
            $value,
            $timeEnd + 1,
            $syntaxEnd - $timeEnd - 1,
        );
        $lengthRaw = substr(
            $value,
            $syntaxEnd + 1,
            $lengthEnd - $syntaxEnd - 1,
        );
        $data = substr(
            $value,
            $lengthEnd + 1,
        );

        self::assertSyntaxOid($syntaxOid);
        $length = self::parseLength($lengthRaw);
        self::assertDataLength(
            $length,
            $data,
        );

        return new self(
            self::parseTime($timeRaw),
            $syntaxOid,
            $data,
        );
    }

    /**
     * Build a history entry for a stored password value, defaulting the syntax to Octet String per RFC 4517.
     */
    public static function forStoredPassword(
        DateTimeImmutable $changedAt,
        string $storedPassword,
        string $syntaxOid = SyntaxOid::OID_OCTET_STRING,
    ): self {
        return new self(
            $changedAt,
            $syntaxOid,
            $storedPassword,
        );
    }

    /**
     * Encode as the pwdHistory attribute value.
     */
    public function encode(): string
    {
        return sprintf(
            '%s#%s#%d#%s',
            GeneralizedTime::format($this->changedAt),
            $this->syntaxOid,
            strlen($this->data),
            $this->data,
        );
    }

    /**
     * @throws PasswordPolicyException
     */
    private static function expectDelimiter(
        string $value,
        int $from,
        string $segmentLabel,
    ): int {
        $position = strpos(
            $value,
            '#',
            $from,
        );
        if ($position === false) {
            throw new PasswordPolicyException(sprintf(
                'Invalid pwdHistory value: missing %s delimiter.',
                $segmentLabel,
            ));
        }

        return $position;
    }

    /**
     * @throws PasswordPolicyException
     */
    private static function assertSyntaxOid(string $syntaxOid): void
    {
        if ($syntaxOid === '') {
            throw new PasswordPolicyException(
                'Invalid pwdHistory value: empty syntax OID.',
            );
        }
    }

    /**
     * @throws PasswordPolicyException
     */
    private static function parseLength(string $raw): int
    {
        if ($raw === '' || !ctype_digit($raw)) {
            throw new PasswordPolicyException(
                'Invalid pwdHistory value: length is not a non-negative integer.',
            );
        }

        return (int) $raw;
    }

    /**
     * @throws PasswordPolicyException
     */
    private static function assertDataLength(
        int $declared,
        string $data,
    ): void {
        $actual = strlen($data);
        if ($actual !== $declared) {
            throw new PasswordPolicyException(sprintf(
                'Invalid pwdHistory value: declared length %d does not match data length %d.',
                $declared,
                $actual,
            ));
        }
    }

    /**
     * @throws PasswordPolicyException
     */
    private static function parseTime(string $raw): DateTimeImmutable
    {
        try {
            return GeneralizedTime::parse($raw);
        } catch (InvalidArgumentException $cause) {
            throw new PasswordPolicyException(
                sprintf(
                    'Invalid pwdHistory value: time "%s" is not a valid GeneralizedTime.',
                    $raw,
                ),
                previous: $cause,
            );
        }
    }
}
