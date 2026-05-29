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

namespace FreeDSx\Ldap\Ldif;

use ArrayIterator;
use Countable;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Ldif\Loader\LdifLoaderInterface;
use FreeDSx\Ldap\Ldif\Loader\StringLdifLoader;
use FreeDSx\Ldap\Operation\Request\AddRequest;
use FreeDSx\Ldap\Operation\Request\DeleteRequest;
use FreeDSx\Ldap\Operation\Request\ModifyDnRequest;
use FreeDSx\Ldap\Operation\Request\ModifyRequest;
use FreeDSx\Ldap\Operation\Request\RequestInterface;
use IteratorAggregate;
use Traversable;

use function array_filter;
use function array_map;
use function array_values;
use function count;

/**
 * The full outcome of an LDIF parse: write requests in original record order.
 *
 * @implements IteratorAggregate<RequestInterface>
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class LdifChanges implements Countable, IteratorAggregate
{
    /**
     * @var array<RequestInterface>
     */
    private array $requests;

    public function __construct(RequestInterface ...$requests)
    {
        $this->requests = $requests;
    }

    /**
     * Buffers a loader's parsed records into a collection. For streaming, iterate {@see LdifParser::parse()} directly.
     */
    public static function fromLoader(
        LdifLoaderInterface $loader,
        LdifParser $parser = new LdifParser(),
    ): self {
        return new self(...$parser->parse($loader));
    }

    /**
     * Convenience for buffering an in-memory LDIF string via {@see StringLdifLoader}.
     */
    public static function fromString(
        string $ldif,
        LdifParser $parser = new LdifParser(),
    ): self {
        return self::fromLoader(
            new StringLdifLoader($ldif),
            $parser,
        );
    }

    /**
     * @return RequestInterface[]
     */
    public function toArray(): array
    {
        return $this->requests;
    }

    public function count(): int
    {
        return count($this->requests);
    }

    /**
     * @return Traversable<RequestInterface>
     */
    public function getIterator(): Traversable
    {
        return new ArrayIterator($this->requests);
    }

    /**
     * @return list<AddRequest>
     */
    public function adds(): array
    {
        return array_values(array_filter(
            $this->requests,
            fn(RequestInterface $r): bool => $r instanceof AddRequest,
        ));
    }

    /**
     * @return list<ModifyRequest>
     */
    public function modifies(): array
    {
        return array_values(array_filter(
            $this->requests,
            fn(RequestInterface $r): bool => $r instanceof ModifyRequest,
        ));
    }

    /**
     * @return list<DeleteRequest>
     */
    public function deletes(): array
    {
        return array_values(array_filter(
            $this->requests,
            fn(RequestInterface $r): bool => $r instanceof DeleteRequest,
        ));
    }

    /**
     * @return list<ModifyDnRequest>
     */
    public function modifyDns(): array
    {
        return array_values(array_filter(
            $this->requests,
            fn(RequestInterface $r): bool => $r instanceof ModifyDnRequest,
        ));
    }

    public function isAddOnly(): bool
    {
        foreach ($this->requests as $request) {
            if (!($request instanceof AddRequest)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Extracts the Entry from every AddRequest, ignoring any non-add requests.
     *
     * @return list<Entry>
     */
    public function entries(): array
    {
        return array_map(
            fn(AddRequest $r): Entry => $r->getEntry(),
            $this->adds(),
        );
    }
}
