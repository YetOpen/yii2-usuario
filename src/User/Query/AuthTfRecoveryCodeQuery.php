<?php

/*
 * This file is part of the 2amigos/yii2-usuario project.
 *
 * (c) 2amigOS! <http://2amigos.us/>
 *
 * For the full copyright and license information, please view
 * the LICENSE file that was distributed with this source code.
 */

namespace Da\User\Query;

use yii\db\ActiveQuery;

class AuthTfRecoveryCodeQuery extends ActiveQuery
{
    public function whereUserId($userId)
    {
        return $this->andWhere(['user_id' => $userId]);
    }

    public function whereUnused()
    {
        return $this->andWhere(['used_at' => null]);
    }
}
