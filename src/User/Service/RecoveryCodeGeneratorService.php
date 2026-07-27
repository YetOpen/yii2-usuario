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
use Yii;

/**
 * Generates a fresh batch of two-factor-authentication recovery codes for a user.
 *
 * The single entry point, {@see run()}, both issues the initial batch (called from
 * `actionTwoFactorEnable`) and regenerates it (called from a "regenerate" action) —
 * both cases must invalidate whatever codes existed before, so there's only one
 * code path that does it.
 */
class RecoveryCodeGeneratorService implements ServiceInterface
{
    const DEFAULT_CODE_COUNT = 10;
    const DEFAULT_CODE_LENGTH = 10;

    /**
     * @var User
     */
    protected $user;

    /**
     * @var int
     */
    protected $count;

    /**
     * @var int
     */
    protected $length;

    /**
     * @param User $user
     * @param int  $count  how many codes to generate
     * @param int  $length length (in bytes of randomness) of each code
     */
    public function __construct(User $user, $count = self::DEFAULT_CODE_COUNT, $length = self::DEFAULT_CODE_LENGTH)
    {
        $this->user = $user;
        $this->count = $count;
        $this->length = $length;
    }

    /**
     * Deletes any recovery code previously issued to the user, then generates and
     * persists a new batch. Only each code's hash is stored, so the plaintext
     * returned here is the only time it's ever available.
     *
     * @return string[] the plaintext codes, to be shown to the user once
     */
    public function run()
    {
        AuthTfRecoveryCode::deleteAll(['user_id' => $this->user->id]);

        $codes = [];
        for ($i = 0; $i < $this->count; $i++) {
            $code = Yii::$app->security->generateRandomString($this->length);
            $codes[] = $code;

            (new AuthTfRecoveryCode([
                'user_id' => $this->user->id,
                'code_hash' => Yii::$app->security->generatePasswordHash($code),
            ]))->save(false);
        }

        return $codes;
    }
}
