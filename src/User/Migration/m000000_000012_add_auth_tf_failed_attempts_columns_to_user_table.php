<?php

/*
 * This file is part of the 2amigos/yii2-usuario project.
 *
 * (c) 2amigOS! <http://2amigos.us/>
 *
 * For the full copyright and license information, please view
 * the LICENSE file that was distributed with this source code.
 */

namespace Da\User\Migration;

use yii\db\Migration;

/**
 * Adds to `{{%user}}` the count of wrong two factor authentication codes and the time of
 * the last one, used to lock the code step after too many wrong codes
 * (see \Da\User\Service\TwoFactorAttemptLimiter).
 */
class m000000_000012_add_auth_tf_failed_attempts_columns_to_user_table extends Migration
{
    /**
     * {@inheritdoc}
     */
    public function safeUp()
    {
        $this->addColumn('{{%user}}', 'auth_tf_failed_attempts', $this->integer()->notNull()->defaultValue(0));
        $this->addColumn('{{%user}}', 'auth_tf_last_failed_at', $this->integer()->null());
    }

    /**
     * {@inheritdoc}
     */
    public function safeDown()
    {
        $this->dropColumn('{{%user}}', 'auth_tf_failed_attempts');
        $this->dropColumn('{{%user}}', 'auth_tf_last_failed_at');
    }
}
