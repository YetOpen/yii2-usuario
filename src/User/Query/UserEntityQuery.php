<?php

namespace Da\User\Query;

use Da\User\Traits\ModuleAwareTrait;
use yii\db\ActiveQuery;
use yii\db\Expression;

class UserEntityQuery extends ActiveQuery
{
    use ModuleAwareTrait;

    /**
     * Narrows to passkeys that have entered their expiry-warning window: last activity
     * (last_used_at, or created_at as a fallback) between `maxPasskeyAge` and
     * `maxPasskeyAge - passkeyExpirationTimeLimit` days ago.
     */
    public function expiring()
    {
        $module   = $this->getModule();
        $maxDays  = (int) $module->maxPasskeyAge;
        $leadDays = (int) $module->passkeyExpirationTimeLimit;

        $now              = time();
        $warningThreshold = $now - ($maxDays - $leadDays) * 86400;
        $expiryThreshold  = $now - $maxDays * 86400;

        $dateField = new Expression('COALESCE(last_used_at, created_at)');

        return $this->andWhere(['<=', $dateField, $warningThreshold])
                    ->andWhere(['>=', $dateField, $expiryThreshold]);
    }
}
