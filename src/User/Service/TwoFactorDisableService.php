<?php

/*
 * This file is part of the 2amigos/yii2-usuario project.
 *
 * (c) 2amigOS! <http://2amigos.us/>
 *
 * For the full copyright and license information, please view
 * the LICENSE file that was distributed with this source code.
 */

namespace Da\User\Service;

use Da\User\Contracts\ServiceInterface;
use Da\User\Model\AuthTfRecoveryCode;
use Da\User\Model\User;

/**
 * Turns two-factor authentication off for a user: clears the TOTP secret and the
 * chosen channel, and invalidates every recovery code issued to them — none of it
 * is left reusable afterwards, whichever caller triggers the disable (a deliberate
 * settings change, or a recovery-code login forcing it — see
 * {@see \Da\User\Controller\api\v1\SecurityController::actionRecoveryCodeVerify()}).
 */
class TwoFactorDisableService implements ServiceInterface
{
    /**
     * @var User
     */
    protected $user;

    /**
     * @param User $user
     */
    public function __construct(User $user)
    {
        $this->user = $user;
    }

    /**
     * @return bool
     */
    public function run()
    {
        AuthTfRecoveryCode::deleteAll(['user_id' => $this->user->id]);

        return $this->user->updateAttributes([
            'auth_tf_enabled' => '0',
            'auth_tf_key' => null,
            'auth_tf_type' => null,
        ]);
    }
}
