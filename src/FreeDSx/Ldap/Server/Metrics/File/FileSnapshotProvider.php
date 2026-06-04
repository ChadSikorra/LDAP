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

namespace FreeDSx\Ldap\Server\Metrics\File;

use FreeDSx\Ldap\Server\Metrics\MetricsSnapshotProvider;
use FreeDSx\Ldap\Server\Metrics\Snapshot\MetricsSnapshot;

use function file_get_contents;
use function is_array;
use function json_decode;

/**
 * Reads a metrics snapshot another process published to a file.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class FileSnapshotProvider implements MetricsSnapshotProvider
{
    public function __construct(private string $path) {}

    /**
     * Returns an empty snapshot when the file is missing or unreadable, so cn=monitor still serves what it can.
     */
    public function snapshot(): MetricsSnapshot
    {
        $contents = @file_get_contents($this->path);

        if ($contents === false) {
            return new MetricsSnapshot();
        }

        $data = json_decode(
            $contents,
            true,
        );

        if (!is_array($data)) {
            return new MetricsSnapshot();
        }

        return MetricsSnapshot::fromArray($data);
    }
}
