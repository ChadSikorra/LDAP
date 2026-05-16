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

namespace FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo;

use FreeDSx\Ldap\Control\Sorting\SortKey;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\PdoDialectInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SqlFilter\SqlFilterResult;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SqlFilter\SqlFilterUtility;

/**
 * Builds the SQL query for PdoStorage::list().
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class PdoListQueryBuilder
{
    public function __construct(
        private PdoDialectInterface $dialect,
    ) {}

    /**
     * @param SortKey[] $sortKeys
     */
    public function build(
        string $base,
        bool $subtree,
        ?SqlFilterResult $filterResult,
        ?int $sizeLimit,
        array $sortKeys,
    ): SqlQuery {
        $query = match (true) {
            !$subtree => $this->buildChildQuery($base, $filterResult),
            $base === '' => $this->buildRootQuery($filterResult),
            default => $this->buildSubtreeQuery($base, $filterResult),
        };

        if ($sortKeys !== []) {
            $query = $this->appendSortClause(
                $query,
                $sortKeys,
            );
        }

        if ($sizeLimit !== null) {
            $query = $query->appending(' LIMIT ' . $sizeLimit);
        }

        return $query;
    }

    private function buildChildQuery(
        string $base,
        ?SqlFilterResult $filterResult,
    ): SqlQuery {
        $query = new SqlQuery(
            $this->dialect->queryFetchChildren(),
            [$base],
        );

        if ($filterResult === null) {
            return $query;
        }

        return $query->appending(
            ' AND (' . $filterResult->sql . ')',
            $filterResult->params,
        );
    }

    private function buildRootQuery(?SqlFilterResult $filterResult): SqlQuery
    {
        if ($filterResult === null) {
            return new SqlQuery($this->dialect->queryFetchAll());
        }

        return new SqlQuery(
            $this->dialect->queryFetchAll() . ' WHERE (' . $filterResult->sql . ')',
            $filterResult->params,
        );
    }

    private function buildSubtreeQuery(
        string $base,
        ?SqlFilterResult $filterResult,
    ): SqlQuery {
        if ($filterResult === null) {
            return new SqlQuery(
                $this->dialect->querySubtree(),
                [$base],
            );
        }

        return $this->buildFilteredSubtreeQuery(
            $base,
            $filterResult,
        );
    }

    /**
     * Filter drives via the sidecar index; scope suffix is LIKE-checked per candidate.
     */
    private function buildFilteredSubtreeQuery(
        string $base,
        SqlFilterResult $filterResult,
    ): SqlQuery {
        $fetchAll = $this->dialect->queryFetchAll();
        $filterSql = $filterResult->sql;
        $sql = <<<SQL
            $fetchAll WHERE ($filterSql)
            AND (lc_dn = ? OR lc_dn LIKE ? ESCAPE '!')
            SQL;

        $params = $filterResult->params;
        $params[] = $base;
        $params[] = '%,' . SqlFilterUtility::escape($base);

        return new SqlQuery(
            $sql,
            $params,
        );
    }

    /**
     * @param SortKey[] $sortKeys
     */
    private function appendSortClause(
        SqlQuery $query,
        array $sortKeys,
    ): SqlQuery {
        $clauses = [];
        $params = [];

        foreach ($sortKeys as $sortKey) {
            $direction = $sortKey->getUseReverseOrder() ? 'DESC' : 'ASC';
            $clauses[] = $this->dialect->sortKeyClause($direction);
            $params[] = strtolower($sortKey->getAttribute());
        }

        return $query->appending(
            ' ORDER BY ' . implode(', ', $clauses),
            $params,
        );
    }
}
