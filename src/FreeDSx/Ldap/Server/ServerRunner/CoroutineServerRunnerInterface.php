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

namespace FreeDSx\Ldap\Server\ServerRunner;

/**
 * Marks a runner that handles connections concurrently within a single process.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface CoroutineServerRunnerInterface extends ServerRunnerInterface {}
