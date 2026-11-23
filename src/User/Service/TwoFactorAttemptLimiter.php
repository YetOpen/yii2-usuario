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

use Da\User\Model\User;
use Da\User\Module;
use Yii;

/**
 * Limits the two factor authentication codes a user can try: after
 * Module::$twoFactorAuthenticationMaxAttempts wrong codes, no code is checked for that user
 * until Module::$twoFactorAuthenticationLockoutTime seconds have passed since the last one.
 *
 * The count is kept on the user record, not in the session: whoever is guessing controls
 * their own session and could reset a count kept there by dropping the cookie.
 *
 * Every attempt is counted before the code is checked (and the count reset when it is
 * right), so concurrent requests cannot all pass the check on the same stale count.
 */
class TwoFactorAttemptLimiter
{
    /**
     * @var User
     */
    protected $user;
    /**
     * @var int
     */
    protected $maxAttempts;
    /**
     * @var int
     */
    protected $lockoutTime;

    /**
     * @param User $user
     */
    public function __construct(User $user)
    {
        $this->user = $user;
        /** @var Module $module */
        $module = Yii::$app->getModule('user');
        $this->maxAttempts = (int) $module->twoFactorAuthenticationMaxAttempts;
        $this->lockoutTime = (int) $module->twoFactorAuthenticationLockoutTime;
    }

    /**
     * Counts an attempt at a code for the user.
     *
     * @return bool whether the code may be checked; false when the user is locked out
     */
    public function beginAttempt()
    {
        if ($this->maxAttempts <= 0) {
            return true;
        }
        $state = $this->readState();
        if ($state['attempts'] > 0 && $this->windowExpired($state['lastFailedAt'])) {
            $this->reset();
        }
        $this->user->updateCounters(['auth_tf_failed_attempts' => 1]);
        $this->user->updateAttributes(['auth_tf_last_failed_at' => time()]);

        return $this->readState()['attempts'] <= $this->maxAttempts;
    }

    /**
     * Clears the count: called once a code has been accepted.
     */
    public function reset()
    {
        $this->user->updateAttributes(['auth_tf_failed_attempts' => 0, 'auth_tf_last_failed_at' => null]);
    }

    /**
     * @return int seconds left before the user may try a code again (0 if not locked out)
     */
    public function getRemainingLockoutTime()
    {
        $state = $this->readState();
        if ($this->maxAttempts <= 0 || $state['attempts'] <= $this->maxAttempts || $state['lastFailedAt'] === null) {
            return 0;
        }

        return max(0, $state['lastFailedAt'] + $this->lockoutTime - time());
    }

    /**
     * @param int|null $lastFailedAt
     * @return bool
     */
    protected function windowExpired($lastFailedAt)
    {
        return $lastFailedAt === null || time() - $lastFailedAt >= $this->lockoutTime;
    }

    /**
     * Reads the count from the database, not from the model, which may be stale when
     * other requests for the same user run at the same time.
     *
     * @return array{attempts: int, lastFailedAt: int|null}
     */
    protected function readState()
    {
        $row = (new \yii\db\Query())
            ->select(['auth_tf_failed_attempts', 'auth_tf_last_failed_at'])
            ->from($this->user::tableName())
            ->where(['id' => $this->user->id])
            ->one($this->user::getDb());

        return [
            'attempts' => (int) ($row['auth_tf_failed_attempts'] ?? 0),
            'lastFailedAt' => isset($row['auth_tf_last_failed_at']) ? (int) $row['auth_tf_last_failed_at'] : null,
        ];
    }
}
